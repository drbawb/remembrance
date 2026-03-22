defmodule Snapcon.BackupServerTest do
  use Snapcon.DataCase

  alias Snapcon.BackupServer

  @good_pubkey "NGXP5qE21ysW5Pk3VFLTOWsdNEuauYkH9xoRB8xCBto="

  describe "backup server" do
    alias Snapcon.Host

    test "creating hosts with duplicate names should fail" do
      host_a = %{name: "foo", pubkey: @good_pubkey}
      host_b = %{name: "foo", pubkey: @good_pubkey}

      assert {:ok, %Host{} = host} = BackupServer.create_host(host_a)
      assert host.name == "foo"

      assert {:error, %Ecto.Changeset{errors: errors}} = BackupServer.create_host(host_b)
      assert {message,opts} = errors[:name]
      assert String.match?(message, ~r/already.*taken/)
      assert opts[:constraint] == :unique
    end

    test "creating hosts with different names should succeed" do
      host_a = %{name: "foo", pubkey: @good_pubkey}
      host_b = %{name: "bar", pubkey: @good_pubkey}

      assert {:ok, %Host{} = host} = BackupServer.create_host(host_a)
      assert host.name == "foo"

      assert {:ok, %Host{} = host} = BackupServer.create_host(host_b)
      assert host.name == "bar"
    end
  end

  test "creating host with nonsensical pubkey should fail" do
      host_a = %{name: "foo", pubkey: "TBD"}

      # the changeset should be rejected
      assert {:error, changeset} = BackupServer.create_host(host_a)
      %{pubkey: errors} = errors_on(changeset)

      # with a message that the key was not parsed correctly
      assert Enum.any?(errors, fn message ->  
        String.match?(message, ~r/not.*parse/)
      end)
  end
end
