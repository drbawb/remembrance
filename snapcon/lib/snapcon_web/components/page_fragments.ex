defmodule SnapconWeb.PageFragments do
  use Phoenix.Component

  alias Phoenix.LiveView.JS
  import SnapconWeb.LayoutHelpers

  embed_templates "fragments/*"

  attr :class, :any, default: nil
  attr :title, :string, required: true
  attr :subtitle, :string
  attr :rest, :global
  def hero(assigns)

  attr :details, :list, default: []
  def debug_details(assigns) do
    ~H"""
    <details :if={show_debug_details(@details)}>
      <div class="debug-msg" :for={detail <- @details}>
      {detail}
      </div>
    </details>
    """
  end

  attr :caption, :string, default: nil
  attr :class, :any, default: nil
  attr :rest, :global, include: ~w(href method)
  slot :inner_block, required: false
  def button(assigns) do
    ~H"""
    <.link class={["button", @class]} {@rest}>
      {render_slot(@inner_block) || @caption}
    </.link>
    """
  end

  attr :type, :string, default: "text"
  attr :field, Phoenix.HTML.FormField, doc: "field from changeset"
  attr :errors, :list, default: []
  attr :rest, :global

  slot :inner_block, required: true

  def input(assigns) do
    ~H"""
    <label
      class="gr-form-label fl-inline fl-col"
      for={@field.name}
    >
      {render_slot(@inner_block)}

      <div
        :for={{msg, _opts} <- @field.errors}
        class="fl-inline fl-col"
      >
        <span class="gr-form-bad-subtext" }>{msg}</span>
      </div>
    </label>
    <input class="gr-form-label" 
    id={@field.id} name={@field.name} 
    type={@type} value={@field.value} {@rest} />
    """
  end

  attr :txt, :string, default: ""
  attr :rest, :global

  def span(assigns) do
    ~H"""
    <span {@rest}>{@txt}</span>
    """
  end

  ## Core Components

  @doc """
  Renders flash notices.

  ## Examples

      <.flash kind={:info} flash={@flash} />
      <.flash kind={:info} phx-mounted={show("#flash")}>Welcome Back!</.flash>
  """
  attr :id, :string, doc: "the optional id of flash container"
  attr :flash, :map, default: %{}, doc: "the map of flash messages to display"
  attr :title, :string, default: nil
  attr :kind, :atom, values: [:info, :error], doc: "used for styling and flash lookup"
  attr :rest, :global, doc: "the arbitrary HTML attributes to add to the flash container"

  slot :inner_block, doc: "the optional inner block that renders the flash message"

  def flash(assigns) do
    assigns = assign_new(assigns, :id, fn -> "flash-#{assigns.kind}" end)

    ~H"""
    <div
      :if={msg = render_slot(@inner_block) || Phoenix.Flash.get(@flash, @kind)}
      id={@id}
      phx-click={JS.push("lv:clear-flash", value: %{key: @kind}) |> hide("##{@id}")}
      role="alert"
      class={[
        "fixed top-2 right-2 mr-2 w-80 sm:w-96 z-50 rounded-lg p-3 ring-1",
        @kind == :info && "bg-emerald-50 text-emerald-800 ring-emerald-500 fill-cyan-900",
        @kind == :error && "bg-rose-50 text-rose-900 shadow-md ring-rose-500 fill-rose-900"
      ]}
      {@rest}
    >
      <p :if={@title} class="flex items-center gap-1.5 text-sm font-semibold leading-6">
        <span :if={@kind == :info} name="hero-information-circle-mini" class="h-4 w-4" />
        <span :if={@kind == :error} name="hero-exclamation-circle-mini" class="h-4 w-4" />
        {@title}
      </p>
      <p class="mt-2 text-sm leading-5">{msg}</p>
      <button type="button" class="flash-close">
        <.span txt="Dismiss"/>
      </button>
    </div>
    """
  end

  @doc """
  Shows the flash group with standard titles and content.

  ## Examples

      <.flash_group flash={@flash} />
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :id, :string, default: "flash-group", doc: "the optional id of flash container"

  def flash_group(assigns) do
    ~H"""
    <div id={@id}>
      <.flash kind={:info} title={"Success!"} flash={@flash} />
      <.flash kind={:error} title={"Error!"} flash={@flash} />
      <.flash
        id="client-error"
        kind={:error}
        title={"We can't find the internet"}
        phx-disconnected={show(".phx-client-error #client-error")}
        phx-connected={hide("#client-error")}
        hidden
      >
        {"Attempting to reconnect"}
        <.span txt="throbber"/>
      </.flash>

      <.flash
        id="server-error"
        kind={:error}
        title={"Something went wrong!"}
        phx-disconnected={show(".phx-server-error #server-error")}
        phx-connected={hide("#server-error")}
        hidden
      >
        {"Hang in there while we get back on track"}
        <.span txt="throbber"/>
      </.flash>
    </div>
    """
  end

  ## JS Commands

  def show(js \\ %JS{}, selector) do
    JS.show(js,
      to: selector,
      time: 300,
      transition:
        {"transition-all transform ease-out duration-300",
         "opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95",
         "opacity-100 translate-y-0 sm:scale-100"}
    )
  end

  def hide(js \\ %JS{}, selector) do
    JS.hide(js,
      to: selector,
      time: 200,
      transition:
        {"transition-all transform ease-in duration-200",
         "opacity-100 translate-y-0 sm:scale-100",
         "opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"}
    )
  end
end
