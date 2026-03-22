defmodule Snapcon.Repo.Migrations.AddIxHostNameUnique do
  use Ecto.Migration

  def change do
    create unique_index(:hosts, ["name"])
  end
end
