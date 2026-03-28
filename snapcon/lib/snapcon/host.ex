defmodule Snapcon.Host do
  use Ecto.Schema

  import Ecto.Changeset

  require Logger

  schema "hosts" do
    field :name, :string
    field :description, :string
    field :pubkey, :string

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(host, attrs) do
    host
    |> cast(attrs, [:name, :description, :pubkey])
    |> unique_constraint(:name)
    |> validate_required([:name, :pubkey])
    |> validate_ed25519_key(:pubkey)
  end

  defp validate_ed25519_key(changeset, field) do
    with pubkey when not is_nil(pubkey) <- get_field(changeset, field),
         trimmed_key <- String.trim(pubkey),
         {:ok, _} <- verify_bin_length(trimmed_key) do
        changeset
      else
        {:error, {:length, n}} ->
          changeset |> add_error(:pubkey, "key too long (#{n} of 32)")

        err ->
          Logger.error "unknown pubkey error #{inspect(err)}"
          changeset |> add_error(:pubkey, "could not parse pubkey")
    end
  end

  defp verify_bin_length(key) when is_binary(key) do
    try do
      key_b = Base.decode64!(key)

      case byte_size(key_b) do
        32 -> {:ok, key}
        n  -> {:error, {:length, n}}
      end
    rescue
      _ -> {:error, "error parsing ed25519 key"}
    end
  end
end
