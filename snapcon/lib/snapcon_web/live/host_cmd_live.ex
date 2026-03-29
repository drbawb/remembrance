defmodule SnapconWeb.HostCommandLive do
  use SnapconWeb, :live_view

  alias Phoenix.PubSub
  alias Snapcon.DaemonServ

  embed_templates "host_cmd/*"

  require Logger

  def mount(%{"name" => host_name} = _params, _session, socket) do
    PubSub.subscribe(Snapcon.PubSub, "host_bus")

    socket = socket
    |> assign(:host_name, host_name)
    |> assign(:error_list, [])
    |> assign(:datasets, [])

    {:ok, socket}
  end

  def handle_event("ask_list", _params, socket) do
    list_result = DaemonServ.list_datasets(socket.assigns.host_name)

    socket = case list_result do
      {:ok, %{"ZfsList" => %{"list" => datasets}}} -> 

        Logger.debug "got #{inspect(datasets |> Enum.take(3))}"
        socket
        |> assign(:datasets, Enum.map(datasets, &list_ent/1))

      {:error, msg} ->
        Logger.error("could not list host :: #{inspect(msg)}")
        socket
        |> assign(:error_list, [msg])
      end

    {:noreply, socket}
  end

  def handle_event(event, _params, socket) do
    socket = update(socket, :error_list, fn list ->
      ["#{event} did not match an event known to this view" | list]
    end)

    {:noreply, socket}
  end

  def handle_info(msg, socket) do
    socket = update(socket, :error_list, fn list ->
      ["#{inspect(msg)} did not match an info known to this view" | list]
    end)

    {:noreply, socket}
  end

  def render(assigns) do
    dataset(assigns)
  end

  defp list_ent(dataset_str) do
    [name, avail, used, used_snap] = String.split(dataset_str, "\t")
    %{name: name, avail_space: avail, used_space: used, used_snap: used_snap}
  end
end
