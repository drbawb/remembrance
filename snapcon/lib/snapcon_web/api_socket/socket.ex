defmodule SnapconWeb.ApiServer do
  @behaviour WebSock
  @version %{"version" => 0x1001}

  alias Snapcon.DaemonServ
  require Logger

  defp push_signed(msg, flags \\ 0x0000) do
    nonce = :crypto.strong_rand_bytes(16)
    ttl = System.os_time(:second) + 30
    payload = Jason.encode!(msg)
    pl_length = byte_size(payload)
    Logger.debug("len = #{pl_length} => #{inspect(payload)}")
   
    # prepare the message header
    header = <<
      nonce::binary-16,
      ttl::unsigned-64,
      64::unsigned-16,
      pl_length::unsigned-16,
      flags::unsigned-32,
    >>

    # digest & sign the payload
    pl_key = Base.decode64!(@priv)

    pl_digest = :crypto.hash_init(:sha256)
      |> :crypto.hash_update(payload)
      |> :crypto.hash_final()

    Logger.debug "digest => #{inspect(pl_digest)}"

    pl_msg = <<
      nonce::binary-16,
      ttl::unsigned-64,
      pl_digest::binary-32,
    >>

    pl_sig = :crypto.sign(:eddsa, :none, pl_msg, [pl_key, :ed25519])

    if 64 != byte_size(pl_sig) do
      raise "unexpected signature size #{byte_size(pl_sig)}"
    end

    if 32 != byte_size(header) do
      raise "unexpected header size #{byte_size(header)}"
    end

    debug_lens = "(hdr: #{byte_size(header)} sig: #{byte_size(pl_sig)} bin: #{byte_size(payload)})"
    Logger.debug "packet #{debug_lens}: #{inspect(pl_sig)}"

    # output the packet
    packet = <<
      header::binary-size(32),
      pl_sig::binary-size(64),
      payload::binary-size(pl_length),
    >>

    {:binary, packet}
  end

  defp msg_authenticate(), do: %{"Ident" => @version}

  def init(opts) do
    Logger.debug "init called :: #{inspect(opts)}"
    host_name = opts[:id]
    state = %{name: host_name}

    reply = DaemonServ.add_host(host_name, self())
    Logger.debug "ws [registration] :: #{inspect(reply)}"

    case reply do
      :ok ->
        Process.send_after(self(), :keepalive, 10_000)
        {:push, push_signed(msg_authenticate()), state}

      {:error, :already_exists} ->
        term_reason = {:unauthorized, reply}
        term_code = {1000, "another daemon is already registered with that name"}
        {:stop, term_reason, term_code, state}

      {:error, :unregistered_host} ->
        term_reason = {:unauthorized, reply}
        term_code = {1000, "no registration found for host name"}
        {:stop, term_reason, term_code, state}

      err ->
        Logger.warning " handhsake for #{host_name} failed :: #{inspect(err)}"
        term_reason = {:unknown, err}
        term_code = {1000, "unexpected host registration failure"}
        {:stop, term_reason, term_code, state}
        
    end
  end

  def handle_in({text, _opts}, state) do
    {:push, {:text, text <> " ... lmao"}, state}
  end

  def handle_info(:keepalive, state) do
    Process.send_after(self(), :keepalive, 10_000)
    {:push, {:ping, ""}, state}
  end

  def handle_info(%{"ping" => need_reply}, state) do
    Logger.debug "got daemon ping request :: #{need_reply}"
    {:push, push_signed(%{"Ping" => %{"msg" => "you are being summoned, do not resist ..."}}), state}
  end

  def handle_info(info, state) do
    Logger.warning "default ws info handler :: #{inspect(info)}"
  
    {:ok, state}
  end

  def terminate({:error, :closed}, state) do
    Logger.debug "removing peer #{inspect(state[:name])}"

    case state[:name] do
      nil -> Logger.warning("disconnection from unregistered host?")

      host_name -> 
        reply = DaemonServ.remove_host(host_name)
        Logger.debug("ws [registration] :: #{inspect(reply)}")
    end
  end

  def terminate({:error, {:unauthorized, _}}, _state) do
    Logger.warning "disconnect from unauthenticated client"
  end

  def terminate(reason, _state) do
    Logger.warning "unhandled w/s failure :: #{inspect(reason)}"
    Logger.warning "daemon state tracking may be out-of-sync"
  end
end
