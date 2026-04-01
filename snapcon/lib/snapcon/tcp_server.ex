defmodule Snapcon.TcpServer do
  @behaviour :ranch_protocol
  @noise_protocol "Noise_KK_25519_ChaChaPoly_BLAKE2s"


  alias Decibel

  require Logger

  def start_link(ref, transport, opts) do
    Logger.info "starting acceptor"

    pid = spawn_link(__MODULE__, :init, [ref, transport, opts])
    {:ok, pid}
  end

  def init(ref, transport, _opts) do
    {:ok, socket} = :ranch.handshake(ref)
    transport.setopts(socket, active: false)

    case do_noise_handshake(socket, transport) do
      {:ok, hs} ->
        Logger.info("noise client connected: #{inspect(hs)}")
        loop(socket, transport, hs)

      # {:error, reason} ->
      #   Logger.warning("noise handshake failed: #{inspect(reason)}")
      #   transport.close(socket)
    end
  end

  defp loop(socket, transport, hs) do
    case transport.recv(socket, 0, 30_000) do
      {:ok, ciphertext} ->
        Logger.info "read #{byte_size(ciphertext)} bytes from socket"
        loop(socket, transport, hs)

      {:error, :timeout} ->
        loop(socket, transport, hs)

      {:error, :closed} -> :ok

      {:error, reason} ->
        Logger.warning "socket error: #{inspect(reason)}"
        transport.close(socket)
    end
  end

  defp do_noise_handshake(socket, transport) do
    kp = {Base.decode64!(@k_pub), Base.decode64!(@k_priv)}
    kc = Base.decode64!(@c_pub)

    # send handshake
    ini = Decibel.new(@noise_protocol, :ini, %{s: kp, rs: kc})
    msg1 = Decibel.handshake_encrypt(ini)
    msg1_len = byte_size(:erlang.iolist_to_binary(msg1))
    Logger.info "msg1 :: #{inspect(msg1)}"

    :ok = transport.send(socket, <<msg1_len::unsigned-16>>)
    :ok = transport.send(socket, msg1)

    # receive handshake response ;; raises on failure
    {:ok, <<msg2_len::unsigned-16>>} = transport.recv(socket, 2, 30_000)
    Logger.info "going to read handshake (n=#{msg2_len})"

    {:ok, msg2} = transport.recv(socket, msg2_len, 30_000)
    Decibel.handshake_decrypt(ini, msg2)

    # send test message ...
    msg3 = Decibel.encrypt(ini, "hello!")
    :ok = transport.send(socket, msg3)

    {:ok, ini}
  end
end
