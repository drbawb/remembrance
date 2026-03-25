defmodule SnapconWeb.LayoutHelpers do
  @moduledoc """
  This is a collection of utility functions which are either
  useful when invoking a layout component, or they are useful
  when defining the layout itself.
  """

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
  If the `:show_debug_details` config option is off, or if the list of debug
  details is empty, this function inhibits the display of a debugging detail
  panel by returning `false`.
  """
  def show_debug_details([]), do: false

  def show_debug_details(details) when is_list(details), do:
    Application.get_env(:zfs_snapcon, :show_debug_details, false)
end
