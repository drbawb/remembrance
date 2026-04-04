defmodule Snapcon.HostTest do
  use ExUnit.Case, async: true

  alias Snapcon.Host

  # A valid 32-byte key, base64-encoded
  @valid_key Base.encode64(:crypto.strong_rand_bytes(32))

  describe "changeset/2 pubkey validation" do
    test "accepts a valid ed25519 pubkey" do
      cs = Host.changeset(%Host{}, %{name: "myhost", pubkey: @valid_key})
      assert cs.valid?
    end

    test "accepts a key with surrounding whitespace" do
      cs = Host.changeset(%Host{}, %{name: "myhost", pubkey: "  #{@valid_key}  "})
      assert cs.valid?
    end

    test "rejects missing name" do
      cs = Host.changeset(%Host{}, %{pubkey: @valid_key})
      refute cs.valid?
      assert cs.errors[:name]
    end

    test "rejects a pubkey that is not 32 bytes" do
      short_key = Base.encode64(:crypto.strong_rand_bytes(16))
      cs = Host.changeset(%Host{}, %{name: "myhost", pubkey: short_key})
      refute cs.valid?
      assert cs.errors[:pubkey]
    end
  end
end
