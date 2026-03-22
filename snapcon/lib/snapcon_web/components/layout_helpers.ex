defmodule SnapconWeb.LayoutHelpers do

  import Plug.Conn

  @app_assigns [
    :dbg_lines,
    :flash,
    :hero_title,
    :hero_subtitle]

  @doc """
  Filters the list of assigns to only forward ones which are relevant
  to the `SnapconWeb.Layouts.app/1` layout component.
  """
  def splat_app(assigns), do:
    Map.take(assigns, @app_assigns)

  @doc """
  Appends a message to the list of debugging messages in the current
  connection's assigns block. These messages are typically displayed only
  in the `:dev` environment or similar.
  """
  def add_debug_line(conn, message) when is_list(message) do
    messages = Map.get(conn.assigns, :dbg_lines, [])
    assign(conn, :dbg_lines, message ++ messages)
  end

  def add_debug_line(conn, message) when is_binary(message) do
    messages = Map.get(conn.assigns, :dbg_lines, [])
    assign(conn, :dbg_lines, [message | messages])
  end

  @doc """
  If the `:show_debug_details` config option is off, or if the list of debug
  details is empty, this function inhibits the display of a debugging detail
  panel by returning `false`, otherwise it returns `true`.
  """
  def show_debug_details([]), do: false

  def show_debug_details(details) when is_list(details), do:
    Application.get_env(:zfs_snapcon, :show_debug_details, false)
end
