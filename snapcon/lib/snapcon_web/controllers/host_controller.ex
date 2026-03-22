defmodule SnapconWeb.HostController do
  use SnapconWeb, :controller

  alias Snapcon.BackupServer
  alias Snapcon.Host

  require Logger

  def index(conn, _params) do
    hosts = BackupServer.list_hosts()

    conn
    |> put_hero("All Hosts", "Listing of all configured daemons.")
    |> render(:index, hosts: hosts)
  end

  def new(conn, _params) do
    changeset = BackupServer.change_host(%Host{})

    conn
    |> put_hero("New Host", "Configure identity for a new daemon.")
    |> render(:new, changeset: changeset)
  end

  def create(conn, %{"host" => host_params}) do
    case BackupServer.create_host(host_params) do
      {:ok, host} ->
        Logger.debug("creating host :: #{inspect(host)}")

        conn
        |> put_flash(:info, "Host created successfully.")
        |> redirect(to: ~p"/hosts")

      {:error, %Ecto.Changeset{} = changeset} ->
        Logger.error("changeset has errors :: #{inspect(changeset)}")

        render(conn, :new, changeset: changeset)
    end
  end

  def show(conn, %{"id" => id}) do
    host = BackupServer.get_host!(id)

    conn
    |> put_hero(host.name, "Host configuration.")
    |> render(:show, host: host)
  end

  def edit(conn, %{"id" => id}) do
    host = BackupServer.get_host!(id)
    changeset = BackupServer.change_host(host)
    render(conn, :edit, host: host, changeset: changeset)
  end

  def update(conn, %{"id" => id, "host" => host_params}) do
    host = BackupServer.get_host!(id)

    case BackupServer.update_host(host, host_params) do
      {:ok, host} ->
        conn
        |> put_flash(:info, "Host updated successfully.")
        |> redirect(to: ~p"/hosts/#{host}")

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :edit, host: host, changeset: changeset)
    end
  end

  def delete(conn, %{"id" => id}) do
    host = BackupServer.get_host!(id)
    {:ok, _host} = BackupServer.delete_host(host)

    conn
    |> put_flash(:info, "Host deleted successfully.")
    |> redirect(to: ~p"/hosts")
  end

  defp put_hero(conn, title, subtitle \\ "") do
    conn
    |> assign(:hero_title, title)
    |> assign(:hero_subtitle, subtitle)
  end
end
