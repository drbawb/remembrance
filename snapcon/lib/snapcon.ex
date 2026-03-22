defmodule Snapcon do
  @moduledoc """
  `remembrance` is an administration console to manage the automation of
  snapshot creation, snapshot thinning, and filesystem replication. 

  This module contains the core logic for scheduling & monitoring the `cyrene`
  daemons which are managed by the controller exposed via the `SnapconWeb` API.
  Each daemon exposes an administrative interface for managing the ZFS pools
  and datasets on that host.
  """
end
