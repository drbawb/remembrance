defmodule SnapconWeb.HostController do
  use SnapconWeb, :controller

  alias Snapcon.BackupServer
  alias Snapcon.DaemonServ
  alias Snapcon.Host

  require Logger

  def index(conn, _params) do
    hosts = BackupServer.list_hosts()

    conn
    |> put_hero("All Hosts", "Listing of all configured daemons.")
    |> render(:index, hosts: hosts)
  end

  def new(conn, params) do
    changeset = BackupServer.change_host(%Host{})
    return = Map.get(params, "return", "index")

    conn
    |> put_hero("New Host", "Configure identity for a new daemon.")
    |> assign(:return, return)
    |> render(:new, changeset: changeset)
  end

  def create(conn, %{"host" => host_params} = params) do
    return = Map.get(params, "return", "index")

    case BackupServer.create_host(host_params) do
      {:ok, host} ->
        Logger.debug("creating host :: #{inspect(host)}")

        conn
        |> put_flash(:info, "Host created successfully.")
        |> redirect_ret(return, host.id)

      {:error, %Ecto.Changeset{} = changeset} ->
        Logger.error("changeset has errors :: #{inspect(changeset)}")

        conn
        |> assign(:return, return)
        |> render(:new, changeset: changeset)
    end
  end

  def show(conn, %{"id" => id}) do
    host = BackupServer.get_host!(id)

    conn
    |> put_hero(host.name, "Host configuration.")
    |> render(:show, host: host)
  end

  def edit(conn, %{"id" => id} = params) do
    host = BackupServer.get_host!(id)
    changeset = BackupServer.change_host(host)
    return = Map.get(params, "return", "show")

    conn
    |> assign(:return, return)
    |> render(:edit, host: host, changeset: changeset)
  end

  def update(conn, %{"id" => id, "host" => host_params} = params) do
    host = BackupServer.get_host!(id)
    return = Map.get(params, "return", "show")

    case BackupServer.update_host(host, host_params) do
      {:ok, _host} ->
        conn
        |> put_flash(:info, "Host updated successfully.")
        |> redirect_ret(return, id)

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> assign(:return, return)
        |> render(:edit, host: host, changeset: changeset)
    end
  end

  def delete(conn, %{"id" => id}) do
    host = BackupServer.get_host!(id)

    {:ok, _host} = BackupServer.delete_host(host)

    conn
    |> put_flash(:info, "Host deleted successfully.")
    |> redirect(to: ~p"/hosts")
  end

  def ping(conn, %{"id" => id}) do
    host = BackupServer.get_host!(id)
    resp = DaemonServ.ping(host.name)

    case resp do
      :ok ->
        conn
        |> put_flash(:info, "Host pinged successfully.")
        |> redirect(to: ~p"/hosts/#{host.id}")

      err ->
        conn
        |> add_debug_line("[daemonserv] [err] :: #{inspect(err)}")
        |> put_flash(:error, "Error pinging host.")
        |> redirect(to: ~p"/hosts/#{host.id}")
    end

  end

  defp redirect_ret(conn, return, id) do
    Logger.debug "return :: #{return} for #{id}"

    path = case return do
      "index" -> ~p"/hosts"
      "show"  -> ~p"/hosts/#{id}"
    end

    conn |> redirect(to: path)
  end

  defp put_hero(conn, title, subtitle) do
    conn
    |> assign(:hero_title, title)
    |> assign(:hero_subtitle, subtitle)
  end
end
