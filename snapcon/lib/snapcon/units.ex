defmodule Snapcon.Units do
  @units [
    {"T", 1024 ** 4},
    {"G", 1024 ** 3},
    {"M", 1024 ** 2},
    {"K", 1024 ** 1}]

  def display(amt) when is_binary(amt) do
    {amt, _} = Integer.parse(amt)
    display(amt)
  end

  def display(amt) when amt >= 0, do: display_r(amt, @units)
  def display(amt), do: ("-" <> display_r(amt * -1, @units))

  defp display_r(amt, []), do: "#{amt}B"

  defp display_r(amt, [_]) when is_nil(amt), do: "NIL"

  defp display_r(amt, [{unit,scale} | t]) when not is_nil(amt) do
    cond do
      amt >= scale -> 
        decimal_str = :erlang.float_to_binary(amt / scale, [decimals: 2])
        decimal_str <> unit

      true -> display_r(amt, t)
    end
  end
end
