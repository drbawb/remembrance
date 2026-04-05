defmodule SnapconWeb.HostCommandLive do
  use SnapconWeb, :live_view

  alias Phoenix.PubSub
  alias Snapcon.DaemonServ
  alias Snapcon.ZfsTree
  alias Snapcon.ZfsNode

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
        socket
        |> assign(:datasets, Enum.map(datasets, &cast_list_ent/1))

      {:ok, %ZfsTree{ list: roots }} ->
        socket
        |> assign(:datasets, ZfsTree.flatten(roots))

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

  @spec cast_list_ent(map()) :: ZfsNode.t()
  defp cast_list_ent(dset_obj) do
    %ZfsNode{} 
    |> ZfsNode.changeset(dset_obj)
    |> Ecto.Changeset.apply_action!(:parse)
  end
end
