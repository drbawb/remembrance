defmodule SnapconWeb.ApiServer do
  @behaviour WebSock

  require Logger

  def init(opts) do
    Logger.debug "init called :: #{inspect(opts)}"
    {:ok, [todo: "something"]}
  end

  def handle_in({text, _opts}, state) do
    {:reply, :ok, {:text, text}, state}
  end

  def handle_info(_, state) do
    {:ok, state}
  end
 
  def terminate(reason, _state) do
    Logger.debug "disconnected w/s: #{inspect(reason)}"
  end
end
