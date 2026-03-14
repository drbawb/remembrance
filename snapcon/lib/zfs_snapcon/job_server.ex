defmodule Snapcon.JobServer do
  use GenServer

  alias Snapcon.Task, as: RepoTask
  alias Phoenix.PubSub
  require Logger

  # Server API

  @doc """
  start_link/1 suitable for running in a supervision tree
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  adds a job of the form `Snapcon.Task.t()` to the run queue.

  if the queue is in a runnable state (i.e. `run_queue` has been called,
  and the inhibit flag has not been raised by the user, or by the queue
  naturally emptying) then the job server will immediately call the scheduler
  in an attempt to find a worker for this job.
  """
  @spec add_job(Snapcon.Task.t()) :: {integer, integer}
  def add_job(job) do
    GenServer.call(__MODULE__, {:add_job, job})
  end

  @doc """
  adds a subjob of the form `Snapcon.Task.t()` to the run queue.

  if the queue is in a runnable state (i.e. `run_queue` has been called,
  and the inhibit flag has not been raised by the user, or by the queue
  naturally emptying) then the job server will immediately call the scheduler
  in an attempt to find a worker for this job.
  """
  @spec add_subjob(integer, Snapcon.Task.t()) :: {integer, integer}
  def add_subjob(parent_id, job) do
    GenServer.call(__MODULE__, {:add_subjob, parent_id, job})
  end

  @doc """
  puts the queue in a runnable state and invokes the scheduler immediately.
  (this has the side-effect of deasserting the `inhibit` flag.)
  """
  def run_queue() do
    GenServer.cast(__MODULE__, :run_queue)
  end

  @doc """
  stops the queue by asserting the `inhibit` flag
  """
  def stop_queue() do
    GenServer.cast(__MODULE__, :inhibit_run)
  end

  @doc """
  gets the current length of the job queue.
  """
  def len_queue() do
    GenServer.call(__MODULE__, :len_queue)
  end

  @doc """
  empties the `work/` and `output/` directories; useful for testing.
  """
  def do_cleanup() do
    GenServer.cast(__MODULE__, :do_cleanup)
  end

  # Callbacks

  @impl true
  def init(opts \\ []) when is_list(opts) do
    Logger.info "booting job server ... #{inspect opts}"

    if is_nil(opts[:root_dir]) do
      raise ArgumentError, "`:root_dir` must be provided, which is the parent of all other paths"
    end

    if is_nil(opts[:work_path]) do
      raise ArgumentError, "`:work_path` must be provided, which will store temporary data for the job"
    end

    if is_nil(opts[:out_path]) do
      raise ArgumentError, "`:out_path` must be provided, which will store the final converted repos"
    end

    workers = for _ <- 1..4 do
      pid = spawn(fn -> worker_loop() end)
      ref = Process.monitor(pid)
      {ref, pid}
    end

    jobtab_t = :ets.new(:jobtab, [:set, :protected])
    jobctr_t = :ets.new(:jobctr, [:set, :protected])
    :ets.insert(jobctr_t, {:next_job, 0})
    PubSub.broadcast(Snapcon.PubSub, "job_dashboard", {:refresh, :jobtab})

    {:ok, %{
      # basic configuration
      root_dir:  opts[:root_dir],
      work_path: opts[:work_path],
      out_path:  opts[:out_path],

      do_cleanup: opts[:do_cleanup] || false,

      jobtab: jobtab_t,
      jobctr: jobctr_t,

      worker_pids: workers,
      idle_queue: :queue.new(),
      job_queue: :queue.new(),
      inhibit_run: true,
    }, {:continue, :init_cleanup}}
  end

  @impl true
  def handle_cast(:run_queue, state) do
    # NOTE: queue/len is O(n) !
    Logger.debug "request to run queue of len: #{:queue.len(state.job_queue)}"
    runnable_state = Map.delete(state, :inhibit_run)
    {:noreply, assign_pending_jobs(runnable_state)}
  end

  @impl true
  def handle_cast(:do_cleanup, state) do
    work_stat = cleanup_dir(true, work_path(state))
    out_stat = cleanup_dir(true, out_path(state))
    Logger.info "work cleanup? #{inspect(work_stat)}"
    Logger.info "output cleanup? #{inspect(out_stat)}"

    out_split = File.mkdir_p(Path.join(out_path(state), "splits"))
    out_rw    = File.mkdir_p(Path.join(out_path(state), "rewrites"))
    Logger.info "split folder? #{inspect(out_split)} @ #{Path.join(out_path(state), "splits")}"
    Logger.info "rewrite folder? #{inspect(out_rw)}  @ #{Path.join(out_path(state), "rewrites")}"

    {:noreply, state}
  end

  @impl true
  def handle_cast({:mark, new_status, id}, state) do
    {_, job} = :ets.lookup(state.jobtab, id) |> hd()
    :ets.insert(state.jobtab, {id, %{job | status: new_status}})
    PubSub.broadcast(Snapcon.PubSub, "job_dashboard", {:refresh, :jobtab})
    {:noreply, state}
  end

  @impl true
  def handle_cast(:inhibit_run, state) do
    {:noreply, Map.put(state, :inhibit_run, true)}
  end
 
  @impl true
  def handle_call({:add_job, job}, _from, state) do
    # assign next job ID/SEQ
    next_id = :ets.update_counter(state.jobctr, :next_job, {2, 1})
    next_seq = :ets.update_counter(state.jobctr, next_id, {2, 1}, {next_id, 0})
    Logger.debug "got next id :: #{inspect(next_id)} / #{inspect(next_seq)}"

    # add to run queue
    job = %{job | id: {next_id, next_seq}}
    new_queue = :queue.in(job, state.job_queue)

    # store in ETS table
    # TODO: depending on how much we are serializing, maybe don't store the 
    # whole job here; but just some header for the LiveView ...
    job_data = %{
      id: {next_id, next_seq},
      ctx: job,
      status: :pending,
    }

    :ets.insert(state.jobtab, {{next_id, next_seq}, job_data})
    PubSub.broadcast(Snapcon.PubSub, "job_dashboard", {:refresh, :jobtab})

    run_state = assign_pending_jobs(%{state | job_queue: new_queue})
    {:reply, {next_id, next_seq}, run_state}
  end

  @impl true
  def handle_call({:add_subjob, next_id, job}, _from, state) do
    # assign next job ID/SEQ
    next_seq = :ets.update_counter(state.jobctr, next_id, {2, 1}, {next_id, 0})
    Logger.debug "got next id :: #{inspect(next_id)} / #{inspect(next_seq)}"

    # add to run queue
    job = %{job | id: {next_id, next_seq}}
    new_queue = :queue.in(job, state.job_queue)

    # store in ETS table
    # TODO: depending on how much we are serializing, maybe don't store the 
    # whole job here; but just some header for the LiveView ...
    job_data = %{
      id: {next_id, next_seq},
      ctx: job,
      status: :pending,
    }

    :ets.insert(state.jobtab, {{next_id, next_seq}, job_data})
    PubSub.broadcast(Snapcon.PubSub, "job_dashboard", {:refresh, :jobtab})

    run_state = assign_pending_jobs(%{state | job_queue: new_queue})
    {:reply, {next_id, next_seq}, run_state}
  end

  @impl true
  def handle_call(:len_queue, _from, state) do
    {:reply, :queue.len(state.job_queue), state}
  end

  @impl true
  def handle_call(:jobtab, _from, state) do
    {:reply, state.jobtab, state}
  end

  @impl true
  def handle_call({:get_job, {id,seq}}, _from, state) do
    {:reply, :ets.lookup(state.jobtab, {id,seq}), state}
  end

  defp assign_pending_jobs(%{inhibit_run: true} = state) do
    Logger.info "ignoring request to run while inhibit enabled"
    state
  end

  defp assign_pending_jobs(state) do
    Logger.debug "schedule [#{:queue.len(state.job_queue)} jobs] [#{:queue.len(state.idle_queue)} workers]"

    case {:queue.out(state.idle_queue), :queue.out(state.job_queue)} do
      {{{:value, worker_pid}, new_idle_queue}, {{:value, job}, new_job_queue}} ->
        Logger.debug "assignment of #{inspect job} to #{inspect worker_pid} possible ..."
        send(worker_pid, {:run, job})
        assign_pending_jobs(%{state | idle_queue: new_idle_queue, job_queue: new_job_queue})

      _ -> state # no more assignments possible
    end
  end

  @impl true
  def handle_continue(:init_cleanup, state) do
    work_stat = cleanup_dir(state.do_cleanup, work_path(state))
    out_stat = cleanup_dir(state.do_cleanup, out_path(state))
    Logger.info "work cleanup? #{inspect(work_stat)}"
    Logger.info "output cleanup? #{inspect(out_stat)}"

    {:noreply, state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    Logger.warning "#{inspect pid} has gone DOWN"
    {:noreply, state}
  end

  @impl true
  def handle_info({:idle, pid}, state) do
    Logger.info "#{inspect pid} is looking for work"
    new_idle_q = :queue.in(pid, state.idle_queue)
    run_state  = assign_pending_jobs(%{state | idle_queue: new_idle_q})
    {:noreply, run_state}
  end

  defp worker_loop() do
    Logger.debug "waiting for work ..."
    send(__MODULE__, {:idle, self()})

    receive do
      {:run, job_details} ->
        try do
          res = process_job(job_details)

          case res do 
            {:error, _} ->
              GenServer.cast(__MODULE__, {:mark, :failed, job_details.id})

            {:ok, _} ->
              GenServer.cast(__MODULE__, {:mark, :complete, job_details.id})
            
            :ok ->
              GenServer.cast(__MODULE__, {:mark, :complete, job_details.id})

            err ->
              Logger.error "job failed w/ unknown reason :: #{inspect(err)}"
              GenServer.cast(__MODULE__, {:mark, :unknown, job_details.id})
          end
        rescue
          err ->
            Logger.error("job failed w/ exception: #{inspect err}")
            GenServer.cast(__MODULE__, {:mark, :failed, job_details.id})
        end

        worker_loop()

      :shutdown -> :ok
    end
  end

  defp process_job(job_details) do
    Logger.debug "running job :: #{inspect job_details}"
    GenServer.cast(__MODULE__, {:mark, :running, job_details.id})

    _job_result = case job_details do
      %RepoTask{job_type: :zfs_snapshot, job_opts: _opts} = _ ->
        Logger.debug "unimplemented job type: zfs snapshot"

      %RepoTask{job_type: :zfs_replicate, job_opts: _opts} = _ ->
        Logger.debug "unimplemented job type: zfs replicate"

      _ ->
        Logger.debug "unknown job :: #{inspect job_details}"
        {:error, :unknown_job}
    end
  end

  defp work_path(opts), do: Path.join(opts[:root_dir], opts[:work_path])
  defp out_path(opts), do: Path.join(opts[:root_dir], opts[:out_path])

  defp cleanup_dir(false, _dir), do: :skipped
  defp cleanup_dir(true, dir) do
    Logger.info "cleaning up #{dir}"

    with true <- File.exists?(dir),
         {:ok, _files} <- File.rm_rf(dir) 
    do
      :ok
    else
      err -> Logger.error "could not remove #{dir}: #{inspect(err)} "
    end

    File.mkdir(dir)
  end
end
