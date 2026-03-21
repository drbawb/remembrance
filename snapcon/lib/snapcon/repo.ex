defmodule Snapcon.Repo do
  use Ecto.Repo,
    otp_app: :zfs_snapcon,
    adapter: Ecto.Adapters.SQLite3
end
