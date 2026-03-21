defmodule SnapconWeb.LiveFragments do
  use Phoenix.Component

  embed_templates "fragments/*"

  attr :errors, :list, required: true
  def live_error_list(assigns)
end
