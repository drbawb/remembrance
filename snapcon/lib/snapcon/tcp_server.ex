defmodule Snapcon.TcpServer do
  use ThousandIsland.Handler

  alias Decibel
  alias Snapcon.DaemonServ
  alias ThousandIsland.Socket, as: TCP
  require Logger

  defmodule HandlerState do
    @derive {Inspect, except: [:socket]}

    @moduledoc """
    Represents an active connection with an established Noise tunnel.
    """

    @typedoc """
    - `noise`: opaque reference returned by the Noise protocol library
    - `assigns`: storage for application variables
    """
    @type t :: %__MODULE__ {
      socket: ThousandIsland.Socket.t(), noise: reference(), assigns: map()
    }

    defstruct socket: nil, noise: nil, assigns: %{}
  end

  defmodule Header do
    @moduledoc """
    After early initialization each packet binary starts with the following header:

    ```
    header:
    nonce    : [u8; 16] ;; 128-bit unsigned integer
    expiry   : u64      ;; 64-bit unix timestamp (seconds from epoch)
    flags    : u32      ;; flag word used for multi-part messages etc.
    pay_len  : u16      ;; payload length, should be <= (64 * 1024)
    reserved : u16      ;; reserved word for future flags

    payload:
    [u8; pay_len] : buf_payload

    add'l payload:
    [u8; ...]     : any contents after `pay_len` is invalid unless the `flags` or
                    `reserved` registers reference data in this region.
    ```

    This module stores this structure as an Erlang-term. The total packet size
    must not exceed 64KiB, the payload length *DOES NOT* include the size of
    the header, as such a payload must never be more than `2^16 - 32 bytes`.
    """

    @typedoc """
    - `nonce`: if not provided it is 16 random bytes from the system CSPRNG
    - `ttl`: 64-bit unix timestamp, defaults to +30s in the future
    - `flags`: protocol bitfield, defaults to 0
    - `reserved`: protocol bitfield, defaults to 0
    - `len`: the length of the payload contents NOT INCLUDING this header
    """
    @type t :: %__MODULE__ {
      nonce: <<_::16>>,
      ttl: <<_::8>>,
      flags: <<_::4>>,
      reserved: <<_::2>>,
      len: <<_::2>>}

    defstruct [
      nonce: :crypto.strong_rand_bytes(16),
      ttl: System.os_time() + 30,
      flags: 0, reserved: 0, len: 0]

  end

  @noise_protocol "Noise_KK_25519_ChaChaPoly_BLAKE2s"
  @version %{"version" => 0x1001}




  @impl ThousandIsland.Handler
  def handle_connection(socket, state) do
    Logger.info "new TCP connection :: #{inspect(state)}"

    init = %HandlerState{socket: socket}

    state = init
      |> assign(:status, :pending)
      |> assign(:pending, %{})
      |> do_noise_handshake()
      |> send_ident_packet()

    Logger.info "noise handshake success :: #{inspect(state)}"

    {:continue, state}
  end

  @impl ThousandIsland.Handler
  def handle_close(_socket, state) do
    Logger.info "closing TCP connection :: #{inspect(state)}"

    if Map.has_key?(state.assigns, :name) do
      :ok = DaemonServ.remove_host(state.assigns[:name])
    end
  end

  @impl ThousandIsland.Handler
  def handle_timeout(_socket, state) do
    Logger.error "socket timed out :: #{inspect(state)}"

    if Map.has_key?(state.assigns, :name) do
      :ok = DaemonServ.remove_host(state.assigns[:name])
    end
  end

  @impl ThousandIsland.Handler
  def handle_data(data, _socket, state) do
    state = read_packet(state, data)
    {:continue, state}
  end

  @impl GenServer
  def handle_call(msg, from, {socket, state}) do
    Logger.warning "[cyrene] unexpected call [#{inspect(from)}] :: #{inspect(msg)}"
    {:reply, :ok, {socket, state}, socket.read_timeout}
  end


  @impl GenServer
  def handle_cast(msg, {socket, state}) do
    Logger.warning "[cyrene] unexpected cast :: #{inspect(msg)}"
    {:noreply, {socket, state}, socket.read_timeout}
  end

  def handle_info({:list_datasets, ref}, {socket, state}) do
    pending = state.assigns[:pending]
    message = %{"ZfsListDataset" => %{"ent_ty" => "All", "recursive" => true}}

    {state, header} = send_any_packet(state, message)
    state = assign(state, :pending, Map.put(pending, header.nonce, ref))

    {:noreply, {socket, state}, socket.read_timeout}
  end

  @impl GenServer
  def handle_info(msg, {socket, state}) do
    Logger.warning "[cyrene] unexpected info :: #{inspect(msg)}"

    {:noreply, {socket, state}, socket.read_timeout}
  end

  defp assign(state, key, val) when not is_list(key) do
    %{state | assigns: put_in(state.assigns, [key], val) }
  end

  defp assign(state, key, val) do
    %{state | assigns: put_in(state.assigns, key, val) }
  end

  defp send_ident_packet(state) do
    msg_p = Jason.encode!(%{"Ident" => @version})
    msg_e = Decibel.encrypt(state.noise, msg_p)
    msg_l = byte_size(:erlang.iolist_to_binary(msg_e))

    nonce = :crypto.strong_rand_bytes(16)
    ttl = System.os_time(:second) + 30
    flags = 0
    reserved = 0

    # prepare the message header
    header = <<nonce::binary-16, ttl::unsigned-64>>
          <> <<flags::unsigned-32>> <> <<reserved::unsigned-16>>
          <> <<msg_l::unsigned-16>>

    TCP.send(state.socket, header)
    TCP.send(state.socket, msg_e)

    state
  end

  defp send_any_packet(state, message) do
    msg_p = Jason.encode!(message)
    msg_e = Decibel.encrypt(state.noise, msg_p)
    msg_l = byte_size(:erlang.iolist_to_binary(msg_e))

    hp = %Header{len: msg_l}

    # prepare the message header
    header = <<hp.nonce::binary-16, hp.ttl::unsigned-64>>
          <> <<hp.flags::unsigned-32, hp.reserved::unsigned-16>>
          <> <<hp.len::unsigned-16>>

    TCP.send(state.socket, header)
    TCP.send(state.socket, msg_e)

    {state, hp}
  end

  defp handle_packet(state, {header, packet}) do
    status = state.assigns[:status]

    state = case status do
      :pending ->
        %{"Ident" => %{"name" => name, "version" => version}} = packet

        :ok = DaemonServ.add_host(name, self())

        state
        |> assign(:status, :ready)
        |> assign(:name, name)
        |> assign(:version, version)

      :ready ->
        case packet do
          %{"ZfsList" => %{"list" => _dsets}} ->
            pending = state.assigns[:pending]
            {reply_ref, pending} = Map.pop!(pending, header.nonce)
            GenServer.reply(reply_ref, {:ok, packet})
            assign(state, :pending, pending)

          msg ->
            Logger.warning "unhandled packet :: #{inspect(msg)}"
            state
        end

      _ -> raise "unhandled status :: #{status}"
    end

    state
  end

  defp read_packet(state, buf) do
    {state, header, tail} = read_header(state, buf)
    {state, msg} = read_message(state, header, tail)
    handle_packet(state, {header, Jason.decode!(msg)})
  end

  defp read_message(state, header, message) do
    {ciphertext, rest} = cond do
      byte_size(message) < header.len ->
        read_message_more(state, header, message)

      byte_size(message) >= header.len ->
        <<pl::binary-size(header.len), tail::binary>> = message
        {pl, tail}
    end

    if byte_size(rest) > 0, do:
      raise "todo: unexpected tail; need continuations ..."

    msg = Decibel.decrypt(state.noise, ciphertext)

    {state, msg}
  end

  defp read_message_more(state, header, buf) do
    case TCP.recv(state.socket, 0, 1_000) do
      {:ok, ciphertext} ->
        read_message(state, header, buf <> ciphertext)

      _ -> {:error, "recv failure during packet decrypt"}
    end
  end

  defp read_header(state, buf) when byte_size(buf) < 32 do
    case TCP.recv(state.socket, 0, 1_000) do
      {:ok, ciphertext} ->
        read_header(state, buf <> ciphertext)

      _ -> {:error, "recv failure during early header decode"}
    end
  end

  defp read_header(state, <<
    nonce::binary-16, ttl::unsigned-64,
    flags::unsigned-32, r::unsigned-16,
    len::unsigned-16, tail::binary
  >>) do

    {state, %{
      nonce: nonce, ttl: ttl,
      flags: flags, reserved: r,
      len: len
    }, tail}
  end

  defp read_header(_state, _buf), do: raise "header not in expected format"

  defp do_noise_handshake(state) do
    kp = {Base.decode64!(@k_pub), Base.decode64!(@k_priv)}
    kc = Base.decode64!(@c_pub)
    socket = state.socket

    # send handshake
    ini = Decibel.new(@noise_protocol, :ini, %{s: kp, rs: kc})
    msg1 = Decibel.handshake_encrypt(ini)
    msg1_len = byte_size(:erlang.iolist_to_binary(msg1))

    :ok = TCP.send(socket, <<msg1_len::unsigned-16>>)
    :ok = TCP.send(socket, msg1)

    # receive handshake response ;; raises on failure
    {:ok, <<msg2_len::unsigned-16, rest::binary>>} = TCP.recv(socket, 2, 30_000)

    {msg2, rest} = cond do
      byte_size(rest) >= msg2_len ->
        <<hs_msg::binary-size(msg2_len), tail::binary>> = rest
        {hs_msg, tail}

      true ->
        rem = msg2_len - byte_size(rest)
        {:ok, <<hs_msg::binary-size(rem), tail::binary>>} = TCP.recv(socket, msg2_len, 30_000)
        {rest <> hs_msg, tail}
    end

    if byte_size(rest) > 0 do
      Logger.warning "unexpected trailing data during handshake :: #{inspect(rest)}"
    end

    Decibel.handshake_decrypt(ini, msg2)

    %{state | noise: ini}
  end
end
