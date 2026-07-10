
# AGENTS.md — perihelion-infrastructure

**Use Tero + cabal-devmelopner for work here.**

## Tero (Layer-1 corpus index)

Repo has `docs/tero-index/index.json` (generated/ refreshed via tero-mcp/scripts/generate_lite_index.py).

**Rule:** Use tero queries before large greps or assumptions.
- Grok: tero__text_search / query_by_id (token "local-dev")
- Direct: tero-mcp-lite --index docs/tero-index/index.json
- cabal-devmelopner: auto-detects local index when run from within this tree (or set TERO_INDEX_PATH).

Example:
```bash
cd /root/git/perihelion-infrastructure
# agent with context:
uv run --project ../cabal-devmelopner cabal-devmelopner "task description here" --use-tero
```

Citations point at file:line — open them.

## Working with cabal-devmelopner agent tool

This project is prepared for integration:
- Tero index committed on chore/tero-index-cabal-ready (and PRable to dev)
- Local auto index support in cabal
- This AGENTS.md

**PR flow (protect main/dev):**
- Create/checkout feature or chore branch
- Make changes (agent will often use working branch)
- PR the branch → `dev` (then dev → main when ready)

## Local checks

Look for:
- scripts/check.sh
- Cargo.toml / pyproject.toml + standard commands (cargo test, uv run pytest, ruff, etc.)

Run checks before considering work complete.

## Further reading

- README.md
- docs/ROADMAP.md or ROADMAP.md (if present)
- docs/ASSESSMENT.md or similar for intent/gaps
- ../cabal-devmelopner/docs/* for agent architecture
- ../tero-mcp for how indexes are built and served

Leave mycelium isolated; all coordination here targets the other repos + cabal.

## Hygiene + thin land (2026-07-09, plan priority 1)
Added `scripts/check.sh` (requirements + pyproject aware via uv/venv/pip, pytest incl security/, advisory black/isort/flake, tero regen modeled on cabal-devmelopner/scripts/check.sh + search-box) and `docs/ROADMAP.md` (minimal living, north star for py infra platform, hygiene/tero, links + waves). Appended here. Tero-first via /root/git/scripts/tero.sh + MCP. Chore branch per branch-guard/dev-workflow; land via dev --no-ff, main --no-ff, push, propagate per plan. Post: update-tero + `./scripts/check.sh` verify. 
Cites: plan.md:90 (thin repos hygiene/landing + perihelion-infrastructure), WORKSPACE_CABAL_TERO_READINESS.md (hygiene tranche, branch), wsfull-wave-2026-07-09-compact.md, perihelion tero index pre/post. 
Run: `./scripts/check.sh` ; `/root/git/scripts/update-tero.sh perihelion-infrastructure` ; tero queries. Make targets remain canonical for full.


## Distribution + Semver (appended)
- Use podman for local GHCR builds (no Actions credits).
- Follow semver from CONTRIBUTING.
- Build: podman build -t ghcr...:<semver> ; podman push.
- Package: python -m build for sdist/wheel.
- Tag: git tag -s v<semver>; gh release create.
- Update pyproject, Dockerfile, helm/k8s examples, docs on bump.
- Tero: text_search "version|release|docker|ghcr".
