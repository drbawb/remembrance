defmodule SnapconWeb.PageFragments do
  use Phoenix.Component

  embed_templates "fragments/*"

  attr :title, :string, required: true
  attr :subtitle, :string
  def hero(assigns)

end
