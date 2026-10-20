# Cycode findings

## Source

- Repository: `RoniTestOrg774/cilium`, Cycode repository id `R_kgDOVPYmgA`, branch `main`.
- Tool: `mcp__cycode__get_v4_violations` (and `_count`). Results larger than the
  token limit are saved to a file. Parse that file (JSON, key `items`) instead of
  reading it into context.
- Fields that matter: `source_policy_name`, `severity`, `risk_score`,
  `detection_details.{file_path, line, cwe}`.

## Counts (open, 2026-10-20)

| Category | Count |
|---|---|
| SAST | 8,498 |
| CI/CD Security + IaC + SecretDetection (+ SCA) | 3,845–3,854 |
| SCA alone | 9 |

Note: free-text `query: "cilium"` also matches other repos that vendor
`github.com/cilium/ebpf` (kata-containers, kubevirt, libnvidia-container). Always
filter by `repository_ids`.

## Observations

- In the top 50 Critical/High SAST findings by risk score, everything in this repo
  except two first-party hits is in `vendor/` (sqlx, ginkgo, helm, go-openapi, the
  alibaba SDK, …). Cilium won't issue advisories for those.
- First-party hits seen so far: see "Leads already seen" in
  [threat-model.md](threat-model.md).

## How the `file_paths` filter behaves (tested 2026-10-20)

- Prefix match, **without a trailing slash**: `"operator"` → 255, `"standalone-dns-proxy"` → 8,
  but `"standalone-dns-proxy/"` → 0. (`"operator/"` happened to work too; don't rely on it.)
- **Passing several paths in one call returns 0** (looks like AND, or broken). One path per call.
- `vendor` alone = 8,026 of ~12.3k open findings. `pkg` = 991.

## Area B + E filter results (2026-10-20)

| Path | Open | Notes |
|---|---|---|
| `operator/pkg/gateway-api` | 230 | ~190 are IaC rules on test YAML; 50 range-loop; 2 cookie flags. **0 prod Critical/High** |
| `pkg/k8s` | 23 | Mostly testutils; 1 prod file-perm (`client/rest_config_provider.go:291`) |
| `pkg/loadbalancer` | 22 | 13 `unsafe` (BPF map marshalling, expected); **Slowloris on `healthserver/healthserver.go:263`** |
| `pkg/envoy` | 11 | OS-command Critical at `standalone_envoy.go:220`; file/dir perms on xDS/accesslog sockets |
| `pkg/policy` | 9 | Range-loop + 1 path-input in `directory/watcher.go:61` (reads local policy dir) |
| `operator/pkg/model` | 7 | All `_test.go` except one range-loop |
| `pkg/datapath/loader` | 7 | OS-command Critical at `compile.go:204`; rest in `verifier_test.go` |
| `operator/pkg/ingress` | 3 | Range-loop only |
| `pkg/ciliumenvoyconfig`, `pkg/annotation` | 0 | |
| `.github` | 25 | **All IaC rules on test manifests** under `.github/actions/`. No workflow-injection findings at all |
| CI/CD Security category | 4 | About the fork's GitHub settings (branch protection etc.), not upstream. Irrelevant |

**B total: ~312 findings, of which roughly 0–3 are worth a look.** Noise sources:

- "Usage of single iteration variable in range loop": `go.mod` is `go 1.27`; per-iteration
  loop variables since Go 1.22 make every one of these a false positive.
- IaC rules firing on test YAML fixtures; `_test.go` / `testutils` hits.
- `unsafe` in BPF map key/value marshalling is intentional.

Triage of the leftovers (first look):

| Finding | Verdict |
|---|---|
| `pkg/envoy/standalone_envoy.go:220` OS command | Args come from agent config (drain time, cap flag). Admin-controlled → likely FP |
| `pkg/datapath/loader/compile.go:204` OS command | Args are `StandardCFlags` + `prog.Options`; need a short trace of `prog.Options`. Likely FP |
| `standalone-dns-proxy/pkg/lookup/lookup.go:89` | `net.ParseCIDR(prefix.String())` — not injection. FP |
| `pkg/loadbalancer/healthserver/healthserver.go:263` no `ReadHeaderTimeout` | **Real but small.** Per-service health server for `externalTrafficPolicy: Local`, binds `:<healthCheckNodePort>` on every node, probed by cloud LBs → possibly internet-reachable (area F, "break it"). Go handles idle conns cheaply; impact likely Low/Medium unless it exhausts agent memory/FDs |

**Conclusion: Cycode SAST adds almost nothing for B and E.** Its rules are pattern-based
(injection sinks, perms); B-takeover bugs are logic/translation bugs, and E needs
GitHub Actions–specific analysis (`pull_request_target`, `workflow_run`, script injection
via `${{ github.event.* }}`) that Cycode isn't reporting for this repo.

## SCA and secrets (verified 2026-10-20)

- **SCA:** all 9 findings are "Use of non-permissive license" (codespell, certifi,
  pyenchant, pathspec, yamllint in docs requirements; go-digest, filepath-securejoin,
  golang-lru in go.mod). **No vulnerable-dependency findings at all.** `is_reachable` is null
  everywhere. Not useful for us.
- **Secrets:** 0 SecretDetection findings (any status).

## Learnings for Cycode (product feedback)

What we hit while using Cycode on this repo, as input for improving the product:

- **API filter quirks.**
  - `file_paths` only prefix-matches without a trailing slash.
  - Passing several `file_paths` values returns 0 instead of their union.
  - Free-text `query: "cilium"` matches other repos that vendor `github.com/cilium/ebpf`.
- **Vendored code dominates.** About 8k of about 12.3k open findings are under `vendor/`.
  A default "first-party only" view, or deprioritizing vendored code unless it sits on an
  attack surface, would remove most of the noise.
- **Rules that should be version- or context-aware.**
  - The range-loop-variable rule fires on a `go 1.27` module, where Go ≥1.22 semantics
    make it a false positive.
  - IaC rules fire on test YAML fixtures.
  - `unsafe` is flagged in BPF map marshalling, where it's intentional.
- **SCA:** only license findings, no reachability data (`is_reachable` null).
- **No CI/workflow findings** for a repo with 97 workflows. The CI/CD findings were about
  the fork's GitHub settings, not workflow content.
- **Where the value is.** Generic pattern rules don't find the bugs that matter for a
  project like this: logic and translation bugs at trust boundaries. Encoding the
  project's threat model as custom rules (Bearer/Semgrep) and as Knowledge Graph queries
  is the direction to explore. That's the feature idea in [README.md](README.md).

## Query plan (original)

Per threat-model area:

- Filter by the area's folders. Drop `vendor/`, `_test.go`, `test/`, `testdata/`,
  `Documentation/`, `examples/`.
- Keep only finding types that fit the area: injection, path traversal and decoding
  problems for A/B; workflow script injection and untrusted checkout for E.
- Check first (one call) whether `file_paths` matches folder prefixes; fall back to
  `query` if it only matches exact files.
