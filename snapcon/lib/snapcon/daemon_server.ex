defmodule Snapcon.DaemonServ do
  use GenServer

  alias Snapcon.Host
  alias Snapcon.Repo
  import Ecto.Query
  require Logger

  defstruct sockets: %{}, pending: %{}

  # Initialization

  def start_link(opts) do
    GenServer.start_link(__MODULE__, {:app_init, opts}, name: __MODULE__)
  end

  def init({:app_init, opts}) do
  Logger.info "booting up daemon monitor:: #{inspect(opts)}"
    {:ok, %__MODULE__{}}
  end

  # API

  @doc """
  Adds the named websocket to the list of tracked daemon sockets.
  """
  def add_host(name, socket) when not is_nil(name) do
    GenServer.call(__MODULE__, {:add_host, name, socket})
  end

  @doc """
  Removes the named websocket from the list of tracked daemon sockets.

  Any pending timers are cancelled and an `{:error, :disconnected}` tuple
  is returned to the awaiting tasks.
  """
  def remove_host(name) do
    GenServer.call(__MODULE__, {:del_host, name})
  end

  def ping(name) do
    GenServer.call(__MODULE__, {:ping, name})
  end

  # Callback Hell

  def handle_call({:add_host, name, socket}, from, state) do
    Logger.debug "dserv [cmd]   :: add host [#{name}] for #{inspect(socket)} via #{inspect(from)}"
    Logger.debug "dserv [state] :: #{inspect(state)}"

    query = from h in Host, where: h.name == ^name
    host = Repo.one(query)

    cond do
      host == nil ->
        {:reply, {:error, :unregistered_host}, state}

      Map.get(state.sockets, name) == nil ->
        new_sockets = Map.put(state.sockets, name, socket)
        {:reply, :ok, %{state | sockets: new_sockets}}

      true ->
        {:reply, {:error, :already_exists}, state}
    end
  end

  def handle_call({:del_host, name}, from, state) do
    Logger.debug "dserv [cmd]   :: del host [#{name}] for #{inspect(from)}"
    Logger.debug "dserv [state] :: #{inspect(state)}"

    cond do
      Map.get(state.sockets, name) == nil ->
        {:reply, {:error, "host was not registered"}, state}

      true ->
        {_host, new_sockets} = Map.pop!(state.sockets, name)
        {:reply, :ok, %{state | sockets: new_sockets}}
    end
  end

  def handle_call({:ping, name}, from, state) do
    Logger.debug "dserv [cmd]   :: ping host [#{name}] for #{inspect(from)}"
    Logger.debug "dserv [state] :: #{inspect(state)}"

    case Map.get(state.sockets, name) do
      nil -> 
        {:reply, {:error, :not_found}, state}

      socket ->
        send(socket, %{"ping" => false})
        {:reply, :ok, state}
    end
  end
end
