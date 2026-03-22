defmodule Snapcon.Host do
  use Ecto.Schema

  alias Eddy.PubKey
  import Ecto.Changeset

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
         {:ok, _key} <- PubKey.from_bin(pubkey, :base64) do
        changeset
      else
        err ->
          changeset |> add_error(:pubkey, "could not parse pubkey", err)
    end
  end
end
