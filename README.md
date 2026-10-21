# rai-swarm

A self-replicating agent. The unit of selection is the Genome. Nodes are cattle.

## Commands

    python rai.py demo      # watch it copy itself, locally
    python rai.py init      # mint the genesis genome
    python rai.py run       # become a node
    python rai.py status    # read the ledger

## Layout

- `rai.py` — everything
- `.github/workflows/spore.yml` — free compute node, every 15 minutes
