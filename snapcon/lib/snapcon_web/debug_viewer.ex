defmodule SnapconWeb.DebugViewer do
  import Plug.Conn

  @assign_var :dbg_lines
  @session_var "sc_debug_lines"

  @doc """
  Retrieve debug details from the session storage
  """
  def fetch_debug_lines(conn, _opts) do
    debug_lines = get_session(conn, @session_var, [])

    conn
    |> assign(@assign_var, debug_lines)
    |> register_before_send(fn conn ->
      debug_lines = conn.assigns[@assign_var] || []


      cond do
        debug_lines == [] -> conn

        is_list(debug_lines) and conn.status in 300..308 ->
          put_session(conn, @session_var, debug_lines)

        true ->
          delete_session(conn, @session_var)
      end
    end)
  end

  @doc """
  Appends a message to the list of debugging messages in the current
  connection's assigns block. These messages are typically displayed only
  in the `:dev` environment or similar.
  """
  def add_debug_line(conn, message) when is_list(message) do
    messages = Map.get(conn.assigns, @assign_var, [])
    put_session(conn, @session_var, message ++ messages)
  end

  def add_debug_line(conn, message) when is_binary(message) do
    messages = Map.get(conn.assigns, @assign_var, [])
    put_session(conn, @session_var, [message | messages])
  end
end
