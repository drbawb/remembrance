defmodule Snapcon.ZfsNode do
  use Ecto.Schema
 
  import Ecto.Changeset

  @type t :: %__MODULE__{}

  @primary_key false
  embedded_schema do
    field :avail, :integer
    field :used, :integer
    field :usedsnap, :integer
    field :name, :string

    embeds_many :children, __MODULE__
  end

  def changeset(node \\ %__MODULE__{}, attrs) do
    node
    |> cast(attrs, [:avail, :used, :usedsnap, :name])
    |> cast_embed(:children, with: &changeset/2)
  end
end

defmodule Snapcon.ZfsTree do
  use Ecto.Schema

  alias Snapcon.ZfsNode

  import Ecto.Changeset

  @type t :: %__MODULE__{}

  @primary_key false
  embedded_schema do
    embeds_many :list, ZfsNode
  end

  def changeset(tree \\ %__MODULE__{}, attrs) do
    tree
    |> cast(attrs, [])
    |> cast_embed(:list)
  end

  @spec flatten([ZfsNode.t()]) :: [ZfsNode.t()]
  def flatten(tree) when is_list(tree) do
    Enum.flat_map(tree, fn node ->
      [%{node | children: []} | flatten(node.children)]
    end)
  end
end
