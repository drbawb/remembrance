defmodule SnapconWeb.Layouts do
  @moduledoc """
  This module holds different layouts used by the console.
  """
  use SnapconWeb, :html

  embed_templates "layouts/*"

  attr :hero_title, :string, default: "Remembrance"
  attr :hero_subtitle, :string, default: "ZFS Snapshot Console"
  attr :flash, :map, required: true, doc: "the map of flash messages"
  slot :inner_block, required: true
  def app(assigns)
end
