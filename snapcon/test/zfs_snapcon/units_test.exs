defmodule Snapcon.UnitsTest do
  use ExUnit.Case, async: true

  alias Snapcon.Units

  describe "display/1 with integer input" do
    test "bytes below 1K" do
      assert Units.display(0) == "0B"
      assert Units.display(1) == "1B"
      assert Units.display(1023) == "1023B"
    end

    test "kilobytes" do
      assert Units.display(1024) == "1.00K"
      assert Units.display(2048) == "2.00K"
      assert Units.display(1024 * 512) == "512.00K"
    end

    test "megabytes" do
      assert Units.display(1024 ** 2) == "1.00M"
      assert Units.display(1024 ** 2 * 100) == "100.00M"
    end

    test "gigabytes" do
      assert Units.display(1024 ** 3) == "1.00G"
      assert Units.display(1024 ** 3 * 2) == "2.00G"
    end

    test "terabytes" do
      assert Units.display(1024 ** 4) == "1.00T"
      assert Units.display(1024 ** 4 * 5) == "5.00T"
    end

    test "negative values are prefixed with minus" do
      assert Units.display(-1024) == "-1.00K"
      assert Units.display(-1) == "-1B"
    end
  end

  describe "display/1 with string input" do
    test "parses string and formats bytes" do
      assert Units.display("0") == "0B"
      assert Units.display("1024") == "1.00K"
      assert Units.display("#{1024 ** 3}") == "1.00G"
    end
  end
end
