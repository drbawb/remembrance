defmodule ZfsSnapcon.Repo.Migrations.CreateHosts do
  use Ecto.Migration

  def change do
    create table(:hosts) do
      add :name, :string
      add :description, :string
      add :pubkey, :string

      timestamps(type: :utc_datetime)
    end
  end
end
