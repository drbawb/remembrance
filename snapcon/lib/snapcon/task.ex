defmodule Snapcon.Task do
  defstruct name: "",
    id: nil,
    status: :unknown,
    job_type: :unknown,
    job_opts: []

  @type t :: %__MODULE__{
    name: String.t(),
    id: {integer, integer},
    status: atom(),
    job_type: atom(),
    job_opts: list(),
  }

end
