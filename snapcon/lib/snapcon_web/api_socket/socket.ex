defmodule SnapconWeb.ApiServer do
  @behaviour WebSock

  alias Snapcon.DaemonServ
  require Logger

  def init(opts) do
    Logger.debug "init called :: #{inspect(opts)}"
    host_name = opts[:id]
    state = %{name: host_name}

    reply = DaemonServ.add_host(host_name, self())
    Logger.debug "ws [registration] :: #{inspect(reply)}"

    case reply do
      :ok ->
        Process.send_after(self(), :keepalive, 10_000)
        {:push, {:text, "hello"}, state}

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
    {:push, {:text, "you are being summoned do not resist"}, state}
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
