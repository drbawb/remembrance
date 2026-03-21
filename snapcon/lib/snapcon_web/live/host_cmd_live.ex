defmodule SnapconWeb.HostCommandLive do
  use SnapconWeb, :live_view

  alias Phoenix.PubSub

  embed_templates "host_cmd/*"

  require Logger

  def mount(_params, _session, socket) do
    PubSub.subscribe(Snapcon.PubSub, "host_bus")

    socket = socket
    |> assign(:error_list, [])
    |> assign(:datasets, [])

    {:ok, socket}
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
end
