defmodule Snapcon.Host do
  use Ecto.Schema
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
  end
end
