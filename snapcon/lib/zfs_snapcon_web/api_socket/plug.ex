defmodule SnapconWeb.ApiServerPlug do
  @behaviour Plug

  @socket_opts [
    timeout: 30_000,
    validate_utf8: true]

  alias SnapconWeb.ApiServer
  import Plug.Conn
  require Logger

  def init(opts \\ []), do: opts

  def call(conn, opts) do
    Logger.debug "api server plug :: #{inspect(opts)}"

    init_opts = extract_init_opts(conn)

    conn
    |> check_subprotocol()
    |> WebSockAdapter.upgrade(ApiServer, init_opts, @socket_opts)
    |> halt()
  end


  defp extract_init_opts(conn) do
    [cyrene_id] = get_req_header(conn, "x-cyrene-id")

    [id: cyrene_id]
  end

  defp check_subprotocol(conn) do
    [req_header] = get_req_header(conn, "sec-websocket-protocol")

    if req_header == "x-cyrene-v1" do
      conn
      |> put_resp_header("sec-websocket-protocol", "x-cyrene-v1")
    else
      conn
      |> resp(:forbidden, "subprotocol not present or unsupported")
      |> send_resp()
      |> halt()
    end
  end
end
