defmodule Snapcon.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    children = [
      SnapconWeb.Telemetry,
      Snapcon.Repo,
      {Ecto.Migrator,
        repos: Application.fetch_env!(:zfs_snapcon, :ecto_repos),
        skip: skip_migrations?()},
      {Phoenix.PubSub, name: Snapcon.PubSub},
      # Start the Finch HTTP client for sending emails
      {Finch, name: Snapcon.Finch},

      # Starts the JobServer, the heart of this application:
      {Snapcon.JobServer,
        root_dir: "/tmp/gitfix",
        out_path: "/output",
        work_path: "/work"},

      {Snapcon.DaemonServ, []},
      daemon_tcp_spec(),
      # Start to serve requests, typically the last entry
      SnapconWeb.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Snapcon.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp daemon_tcp_spec() do
    opts = %{
      socket_opts: [port: 4001],
      num_acceptors: 16,
      max_connections: 1024
    }

    :ranch.child_spec(:cyrene_tcp, :ranch_tcp, opts, Snapcon.TcpServer, [])
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    SnapconWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  defp skip_migrations?() do
    # By default, sqlite migrations are run when using a release
    System.get_env("RELEASE_NAME") != nil
  end
end
