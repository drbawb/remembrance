defmodule SnapconWeb.Router do
  use SnapconWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {SnapconWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :fetch_debug_lines
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/", SnapconWeb do
    pipe_through :browser

    live "/", JobQueueLive
    live "/watch/:name", HostCommandLive
    
    resources "/hosts", HostController
    post "/hosts/:id/ping", HostController, :ping

  end

  # Other scopes may use custom stacks.
  # scope "/api", SnapconWeb do
  #   pipe_through :api
  # end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:zfs_snapcon, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: SnapconWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end
end
