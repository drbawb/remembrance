defmodule SnapconWeb.PageFragments do
  use Phoenix.Component

  embed_templates "page_fragments/*"

  attr :title, :string, required: true
  attr :subtitle, :string
  def hero(assigns)

end
