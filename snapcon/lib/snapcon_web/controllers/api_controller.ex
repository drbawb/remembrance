defmodule SnapconWeb.ApiController do
  @key "SZR+bbVrsKJCYx+P/VMjyVgKCzmTdexKKAOdJoLxlWY="
  # @key "EqBy6+J1j7bENKxoTgEOciOKfyT31XmzLMzGcHR1lnk="
  @verify_actions [:test]

  alias Eddy.PubKey
  use SnapconWeb, :controller
  require Logger

  plug :verify when action in @verify_actions

  def verify(conn, _opts) do
    digest = conn.private[:cyrene_digest]
    signature = conn.private[:cyrene_sig]
    {:ok, key} = PubKey.from_bin(@key, :base64)
    {:ok, sig} = Base.decode64(signature)
    
    case Eddy.verify(sig, digest, key) do
      true -> conn
      false -> 
        conn
        |> send_resp(401, "unauthorized")
        |> halt()
    end
  end

  def test(conn, _params) do
    digest = conn.private[:cyrene_digest]
    signature = conn.private[:cyrene_sig]
    body_len = conn.private[:cyrene_len]

    {:ok, key} = PubKey.from_bin(@key, :base64)
    {:ok, sig} = Base.decode64(signature)

    case Eddy.verify(sig, digest, key) do
      true -> conn
      false -> 
        conn
        |> send_resp(401, "unauthorized")
        |> halt()
    end

    message = %{
      digest: Base.encode16(digest, case: :lower),
      length: body_len,
    }

    json(conn, message)
  end
end
