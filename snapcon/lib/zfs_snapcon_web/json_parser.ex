defmodule SnapconWeb.JsonSigner do

  import Plug.Conn, only: [get_req_header: 2, put_private: 3]

  @moduledoc """
  Stores a digest of the body for use downstream by the crypto verifier.
  """
  def read_body(conn, opts) do
    read_all(conn, opts, :crypto.hash_init(:sha256), [])
  end

  defp read_all(conn, opts, hasher, acc) do
    case Plug.Conn.read_body(conn, opts) do
      {:ok, body, conn} ->
        hasher = :crypto.hash_update(hasher, body)
        full = IO.iodata_to_binary(Enum.reverse([body | acc]))
        digest = :crypto.hash_final(hasher)

        [sig_header] = get_req_header(conn, "x-cyrene-sig")

        conn = conn
          |> put_private(:cyrene_digest, digest)
          |> put_private(:cyrene_sig, sig_header)
          |> put_private(:cyrene_len, String.length(full))

        {:ok, full, conn}

      {:more, body, conn} ->
        hasher = :crypto.hash_update(hasher, body)
        read_all(conn, opts, hasher, [body | acc])
    end
  end
end
