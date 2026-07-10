# perihelion-infrastructure — Roadmap

**Status:** Living (2026-07-09)  
**North star:** Enterprise-grade, security-first Kubernetes infrastructure with GitLab CI/CD automation, full observability (Prometheus/Grafana/AlertManager), defense-in-depth (network policies, RBAC, Pod Security Standards, Vault), and production GitOps.

Companions: [README.md](../README.md), [SECURITY.md](../SECURITY.md), docs/*.md (architecture, impl plan, etc.), [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Current State (per README + tero)

- GitLab Runner Controller (src/gitlab_runner_controller/): auto-scaling, hardened
- k8s/ manifests (namespaces, monitoring, security, logging, vault)
- helm/ charts
- Full Python src + tests/security/
- pyproject.toml (setuptools), requirements{,-dev}.txt , pre-commit, Makefile (install/test/lint/security)
- Tero index (305+ items)

See "🚀 Project Status" in README for completed/in-progress/upcoming.

## Hygiene + Tero

- `scripts/check.sh` added (modeled on cabal-devmelopner + search-box; handles requirements.txt + requirements-dev.txt + pyproject, uv/venv, pytest (unit+security), advisory lint, tero regen via ../tero-mcp)
- `docs/ROADMAP.md` (this; minimal living)
- AGENTS.md appended (hygiene + land section + cites)
- Tero re-index + `/root/git/scripts/update-tero.sh` post edits
- Follows plan.md priority 1 (thin hygiene + land for py infra)
- Run before PR/land: `./scripts/check.sh` (or --fix); consider `make test lint security-scan`

## Waves (minimal / hygiene focus)

| ID | Work |
|----|------|
| PI-H1 | Thin hygiene (check.sh/ROADMAP/AGENTS/land chore) — done |
| PI-1 | Complete supporting services (Vault + logging; current feature branch refs) |
| PI-2 | Full CI (GitHub Actions parity with Makefile targets) + check.sh in workflows |
| PI-3 | Production rollout + advanced scaling/hardening per impl plan |

## Links

- [plan.md](../../plan.md) (priority 1 thin + peri py infra)
- [dev-docs/WORKSPACE_CABAL_TERO_READINESS.md](../../dev-docs/WORKSPACE_CABAL_TERO_READINESS.md)
- [dev-docs/waves/wsfull-wave-2026-07-09-compact.md](../../dev-docs/waves/wsfull-wave-2026-07-09-compact.md)
- docs/gitlab_*.md (detailed)
- cabal-devmelopner + tero-mcp (integration)
- Tero queries: `./scripts/tero.sh perihelion-infrastructure text_search "hygiene" ...`

**Tero-first:** Use before large changes/greps. Every answer has citations + EXPLAIN. Append-only for docs/AGENTS/ROADMAP.

(End of minimal roadmap; append-only.)

## Semver + Distribution Build (chore/semver-ghcr-distribution-build appended)
- Established baseline from git history + docs (initial pyproject 0.1.0, no prior releases; CONTRIBUTING mandates semver MAJOR.MINOR.PATCH + GPG signed tags + release checklist).
- Bumped Python package to 0.2.0 (minor for new distribution build capability).
- Added root Dockerfile (multi-stage prod, security-hardened, matches k8s/helm, uv/pip, cli entry).
- Built Python package (dist/ with 0.2.0 wheels/sdist) and container image locally with **podman** (preferred).
- GHCR artifact: ghcr.io/tzervas/perihelion-infrastructure/gitlab-runner-controller:0.2.0 + :latest pushed.
- Release: will tag v0.2.0 (GPG), gh release.
- Tero-first (queries on version/release/docker/dist), hygiene (check.sh), append-only.
- Cites: plan.md, CONTRIBUTING--version-management--release-process, pyproject, Makefile docker targets, k8s/helm image refs.
