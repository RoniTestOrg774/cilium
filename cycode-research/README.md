# Cycode research on Cilium

## Why we're doing this

The goal of this research is **not** to collect an actual bug bounty. We use a real,
large, security-sensitive open-source project (Cilium) as a test bed to learn how
Cycode can get better:

- **Graph queries that detect threats.** Learn which Cycode Knowledge Graph queries
  can express real threats from a project's threat model. Some of them may be added
  to Cycode's scanners.
- **Threat-model–driven custom rules.** Learn how to turn a threat model into custom
  Bearer rules that find the code paths that matter, so we can offer this to Cycode
  customers as a feature.
- **Signal vs. noise.** Understand why out-of-the-box findings on a repo like this are
  mostly noise, and what would make them useful (see the learnings in
  [cycode.md](cycode.md)).

The bug-bounty framing (attacker positions, chains, "would this get a CVE?") is only
there to keep the work grounded in threats that actually matter.

## Ground rules

- Test only on our own clusters (kind / test clusters). Never against real GKE/AKS
  customer endpoints or anyone else's deployment.
- Anything that looks like a real vulnerability in Cilium goes privately to
  security@cilium.io (see `SECURITY.md`) before it is discussed anywhere public.
- Judge every finding against `Documentation/security/threat-model.rst`.

## Files

- [process.md](process.md) — how we work and the decision log
- [threat-model.md](threat-model.md) — attacker positions, Critical-CVE potential, and a
  gap analysis against Cilium's official threat model
- [cycode.md](cycode.md) — what the Cycode findings looked like, how we queried them, and
  learnings for Cycode
- `graph-query-all-workflows.json` (+ `.min.json`) — Knowledge Graph query listing all
  GitHub Actions workflow files in this repo
