defmodule SnapconWeb.LayoutHelpersTest do
  use ExUnit.Case, async: true

  alias SnapconWeb.LayoutHelpers

  describe "splat_app/1" do
    test "keeps only app-relevant assign keys" do
      assigns = %{
        flash: %{},
        hero_title: "Hello",
        hero_subtitle: "World",
        dbg_lines: [],
        socket: :fake,
        live_action: :index,
        some_other_key: "irrelevant"
      }

      result = LayoutHelpers.splat_app(assigns)
      assert Map.keys(result) |> Enum.sort() == [:dbg_lines, :flash, :hero_subtitle, :hero_title]
      refute Map.has_key?(result, :socket)
      refute Map.has_key?(result, :live_action)
      refute Map.has_key?(result, :some_other_key)
    end

    test "returns empty map when no matching keys present" do
      assert LayoutHelpers.splat_app(%{socket: :fake}) == %{}
    end

    test "returns only present matching keys" do
      result = LayoutHelpers.splat_app(%{flash: %{info: "ok"}})
      assert result == %{flash: %{info: "ok"}}
    end
  end

  describe "show_debug_details/1" do
    test "returns false for empty list" do
      assert LayoutHelpers.show_debug_details([]) == false
    end

    test "returns app config value for non-empty list" do
      configured = Application.get_env(:zfs_snapcon, :show_debug_details, false)
      assert LayoutHelpers.show_debug_details(["some line"]) == configured
    end
  end
end
