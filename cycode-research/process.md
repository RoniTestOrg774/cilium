# Process and decision log

## Approach

1. **Threat model first.** Define attacker positions and the code each one can reach
   ([threat-model.md](threat-model.md)).
2. **Use the model to filter Cycode.** For each area, run one or two Cycode queries
   filtered by its folders and by the finding types that fit it, instead of exporting
   every finding.
3. **Build chains.** A chain needs three links:
   - **Entry:** a finding where attacker input comes in.
   - **Sink:** a finding with a dangerous operation, on the same data path.
   - **Impact:** an effect that crosses a boundary in the threat model, starting from
     the attacker's position.

   Findings without a matching entry or sink are dropped.
4. **Verify.** Check against past GHSAs, reproduce on a local cluster, then write up.

## Decision log

### 2026-10-20

- Exporting all ~12.3k open Cycode findings was abandoned: too many, mostly vendored
  code, and too costly. → Threat-model-driven filtering instead.
- Agreed to discuss before running agents/workflows on our own.
- Added the **external attacker** (internet → GKE Dataplane V2 / AKS) as its own area
  (F). Highest impact, lowest odds, and Cycode SAST is unlikely to help there.
- Proposed split (not yet confirmed):
  - **Main bet:** areas B then A, Cycode-driven. Most likely to give an accepted CVE.
  - **Long-shot track:** area F, manual / differential analysis, run alongside.
- Notes live in this folder (originally a local-only `bounty/` folder).
- Framed attacker actions as get past / take over / break, and scored each cell for
  Critical potential (see [threat-model.md](threat-model.md)).
- **Decision: main critical bets are B-takeover (namespace user → agent/node) and E
  (release pipeline).** F remains a long shot.
- Next: filter Cycode findings to the B and E areas and count them; compare our threat
  model with Cilium's to find what theirs misses.
- Done both (see [cycode.md](cycode.md) and the gap analysis in
  [threat-model.md](threat-model.md)):
  - B area ≈ 312 Cycode findings, ~0–3 worth a look; E has no workflow findings at all.
    Cycode SAST is mostly noise for our critical bets.
  - Best gaps in Cilium's model: namespace-scoped tenant (esp. HTTPRoute/Ingress/Service
    annotations), external north-south attacker, outsider-triggered CI, malformed DNS
    attacking the proxy. Their strong "None" claims (workload/network → agent) are the
    cleanest things to contradict.
  - Side lead: `healthserver` without `ReadHeaderTimeout` on `healthCheckNodePort` (F, DoS).
- Wrote a Knowledge Graph query covering all 97 workflow files
  (`graph-query-all-workflows.json`). The CI/workflow (E) track was not taken further in
  this session.
- Renamed the folder to `cycode-research/` and committed it to the fork to share with the
  team. Clarified the purpose: learning how to improve Cycode (graph queries, scanner
  rules, threat-model–driven custom Bearer rules as a customer feature), not collecting a
  bounty.
- Using Cycode is a requirement of the exercise (our edge). Options considered: custom
  rules encoding our hypotheses, vendored findings filtered to attack-surface libraries,
  SCA reachability, valid secrets, Cycode graph for CI.
- Verified: SCA = 9 license-only findings, secrets = 0 → both dropped. Remaining:
  custom rules, attack-surface vendored findings, graph query for CI.

## Open questions

- Confirm the two-track split and priority order.
- Does Cycode's `file_paths` filter match folder prefixes, or only exact files?
  (One cheap call answers it; fall back to free-text `query` if exact-only.)
- For F: which Cilium features do GKE DPv2 and AKS actually enable (kube-proxy
  replacement, XDP, host firewall, Cilium Ingress/Gateway)? Check public docs first.
