defmodule SnapconWeb.JobQueueLive do
  use SnapconWeb, :live_view

  alias Snapcon.JobServer
  alias Phoenix.PubSub

  require Logger

  def mount(_params, _session, socket) do
    PubSub.subscribe(Snapcon.PubSub, "job_dashboard")

    socket = socket
    |> assign(:error_list, [])
    |> assign_job_list()

    {:ok, socket}
  end

  def handle_event("add_split", _params, socket) do
    Logger.debug "unhandled UI action: add split"
    {:noreply, socket}
  end

  def handle_event("clear_errors", _params, socket) do
    {:noreply, assign(socket, :error_list, [])}
  end

  def handle_event("do_cleanup", _params, socket) do
    JobServer.do_cleanup()
    {:noreply, socket}
  end

  def handle_event("run_table", _params, socket) do
    JobServer.run_queue()
    {:noreply, socket}
  end

  def handle_event("stop_table", _params, socket) do
    JobServer.stop_queue()
    {:noreply, socket}
  end

  def handle_event("kill_server", _params, socket) do
    Process.whereis(Snapcon.JobServer) |> Process.exit(:kill)
    {:noreply, socket}
  end

  def handle_event(event, _params, socket) do
    socket = update(socket, :error_list, fn list ->
      ["#{event} did not match an event known to this view" | list]
    end)

    {:noreply, socket}
  end

  def handle_info({:refresh, :jobtab}, socket) do
    {:noreply, assign_job_list(socket)}
  end

  def handle_info(msg, socket) do
    socket = update(socket, :error_list, fn list ->
      ["#{inspect(msg)} did not match an event known to this view" | list]
    end)

    {:noreply, socket}
  end

  defp assign_job_list(socket) do
    jobtab = GenServer.call(JobServer, :jobtab)
    joblist = :ets.tab2list(jobtab)
    joblist = Enum.sort(joblist, fn ({a,_}, {b,_}) -> a <= b end)
    assign(socket, :job_list, joblist)
  end
end
