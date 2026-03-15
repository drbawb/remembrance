defmodule SnapconWeb.ApiSocket do
  @behaviour Phoenix.Socket.Transport

  require Logger

  def child_spec(opts), do: :ignore

  def connect(state) do
    Logger.debug "api socket connect :: #{inspect(state)}"
    # Callback to retrieve relevant data from the connection.
    # The map contains options, params, transport and endpoint keys.
    {:ok, state}
  end

  def init(state) do
    Logger.debug "api socket init :: #{inspect(state)}"
    # Now we are effectively inside the process that maintains the socket.
    {:ok, state}
  end

  def handle_in({text, _opts}, state) do
    Logger.debug "api socket in <= #{inspect(state)}"
    Logger.debug "message <= #{inspect(text)}"
    {:reply, :ok, {:text, text}, state}
  end

  def handle_info(_, state) do
    Logger.debug "api socket out => #{inspect(state)}"
    {:ok, state}
  end

  def terminate(reason, _state) do
    Logger.debug "request to terminate: #{inspect(reason)}"
    :ok
  end
end
