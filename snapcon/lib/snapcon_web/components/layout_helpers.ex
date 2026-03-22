defmodule SnapconWeb.LayoutHelpers do
  @app_assigns [
    :flash,
    :hero_title,
    :hero_subtitle]

  def splat_app(assigns), do: Map.take(assigns, @app_assigns)
end
