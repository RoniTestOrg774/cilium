# Threat model (working draft)

Based on Cilium's own model in `Documentation/security/threat-model.rst`. That model is
what the Cilium security team judges reports against. Starting positions it treats as
by-design (root on the node, Kubernetes API admin) are out of scope for us.

## Attacker positions

| # | Attacker starts as | Gets in through | Code areas | Bounty-worthy impact |
|---|---|---|---|---|
| A | **Unprivileged pod** | Its own traffic: DNS proxy, L7/Envoy parsing, BPF packet handling | `pkg/fqdn/dnsproxy`, `pkg/proxy`, `proxylib`, `bpf/`, `standalone-dns-proxy/` | Policy bypass, agent crash, code execution in the agent |
| B | **Namespace-scoped K8s user** | Namespaced CRDs and annotations: namespaced Cilium policies, CiliumEnvoyConfig, Gateway/Ingress routes, service and pod annotations | `pkg/policy`, `pkg/ciliumenvoyconfig`, `operator/pkg/gateway-api`, `operator/pkg/ingress`, `pkg/redirectpolicy`, `pkg/annotation` | Reaching into other namespaces, reading Secrets through Envoy, cluster-wide effects |
| C | **Network / other node** | Tunnel traffic, encryption handshakes, clustermesh, the health endpoint | `pkg/wireguard`, `pkg/datapath/linux/ipsec`, `pkg/clustermesh`, `cilium-health` | Breaking encryption or authentication, cross-cluster impersonation |
| D | **Local, low-privilege on the node** | Agent API socket, Hubble, CNI plugin input from kubelet | `api/`, `pkg/hubble`, `plugins/cilium-cni`, `daemon/` | Escalating to the agent's privileges |
| E | **Supply chain** | GitHub workflows (`pull_request_target`, untrusted input in scripts), release and signing jobs | `.github/workflows`, `images/` | Only counts if it reaches release artifacts or signing (per `SECURITY.md`; `quay.io/cilium/*-ci` is out of scope) |
| F | **External attacker** (internet → GKE Dataplane V2 / AKS) | See below | See below | Unauthenticated policy / source-range bypass, remote DoS of nodes |

Code paths above are a first pass and still need confirming against the tree.

## F: External attacker in detail

On GKE Dataplane V2 and on AKS clusters that run Cilium, packets from outside reach
Cilium's BPF datapath before anything else does. Anything exposed through Cilium
Ingress/Gateway API also takes outside HTTP.

| Gets in through | Code areas | Realistic bug classes |
|---|---|---|
| Raw packets to NodePort/LoadBalancer | `bpf/bpf_host.c`, `bpf/bpf_xdp.c`, `bpf/lib/nodeport*.h`, `lb.h`, `nat.h`, `conntrack.h` | Header-parsing confusion: IPv4 fragments, IPv6 extension headers, ICMP errors carrying inner packets that NAT rewrites. Getting around `loadBalancerSourceRanges` or the host firewall. Connection-tracking or NAT table exhaustion (DoS). |
| Outside HTTP into Cilium Ingress/Gateway | `operator/pkg/gateway-api`, `operator/pkg/ingress`, `operator/pkg/model/translation` | Translation bugs: a route, header or path match becomes looser Envoy config than intended, so traffic reaches a backend that should be unreachable or skips an auth route. |
| DNS answers from servers the attacker controls (a pod resolves the attacker's domain) | `pkg/fqdn`, `pkg/fqdn/dnsproxy`, `standalone-dns-proxy/` | Poisoning FQDN policy so it allows the wrong IPs, exhausting policy maps, crashing the proxy |

Notes:

- The kernel verifier makes memory corruption leading to remote code execution very
  unlikely in BPF. A realistic headline bug is a logic bug: bypass or remote DoS.
- Cycode SAST looks for injection-style patterns, so it won't help much here. F needs
  manual or differential analysis: feed malformed packets and compare datapath
  behaviour with policy, or compare Gateway/Ingress resources with the generated
  Envoy config.
- GKE runs Google's own build of Cilium. Confirm which features GKE and AKS actually
  enable before investing effort. A bug in a disabled feature won't matter.
- Envoy itself and Cilium's Envoy filters live in other repos (upstream Envoy,
  `cilium/proxy`). Bugs there are out of scope for this repo but may still be
  reportable.

## What an attacker does to Cilium

From any starting position, there are three things an attacker can do:

- **Get past it.** Cilium is the firewall, so traffic it should block gets through.
- **Take it over.** The agent runs with root-level privileges on every node, so
  controlling it means controlling the node.
- **Break it.** Crash the agent or fill its tables, taking down networking for a node
  or the whole cluster.

| Starts from | Get past it | Take it over | Break it |
|---|---|---|---|
| Inside: pod (A), namespace user (B), low-privilege user on the node (D) | ✓ | ✓ | ✓ |
| Outside: internet (F) | ✓ (most likely) | ✓ (unlikely) | ✓ |
| Network between nodes (C) | ✓ | — | ✓ |
| Release pipeline (E) | — | ✓ (via tampered release) | — |

## Critical-CVE potential (CVSS 3.1 ≥ 9.0)

Best-case scores assume common or default config and a clean exploit. These are our own
estimates; Cilium's security team assigns the real score, and its past advisories have
mostly been Medium or High.

| Cell | Best-case vector | Best case | Odds |
|---|---|---|---|
| F: internet takes over Cilium | AV:N/AC:L/PR:N/UI:N/S:C/H/H/H | 10.0 | Very low (BPF verifier makes RCE very unlikely) |
| F: internet gets past Cilium | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H | 10.0 | Low; uncommon config → AC:H → ~8.6 |
| **B: namespace user takes over agent/node** | AV:N/AC:L/PR:L/UI:N/S:C/H/H/H | 9.9 | **Moderate: best balance of score and odds** |
| A: pod takes over the agent | AV:N/AC:L/PR:L/UI:N/S:C/H/H/H | 9.6 | Low to moderate |
| **E: release pipeline compromise** | AV:N/AC:L/PR:N/UI:N/S:C/H/H/H | up to 10.0 | **Moderate; ~3.8k Cycode CI/CD+IaC findings**; must reach release artifacts or signing |
| C: network attacker breaks encryption/identity | AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H | 9.3 | Low; special conditions → High |
| A/B: tenant gets past policy into another namespace | PR:L, usually C:H/I:L or lower | ~7.5–9.0 | Moderate; most common real Cilium advisory type |

Cannot reach Critical:

- Any "break it" (availability-only) — tops out at ~8.6 for unauthenticated remote DoS.
- D (local attack vector) — capped at ~8.8.

**Main critical bets: B-takeover and E.** F stays a long shot.

## Gap analysis: ours vs. Cilium's official model

Their model (`Documentation/security/threat-model.rst`) has 8 actors: workload,
limited-privilege host, root host, MITM, network, K8s API server, kv-store, Hubble data.

### Where they make a strong "None" claim (contradicting it = a clean report)

| Their claim | Where | What would contradict it |
|---|---|---|
| Workload attacker: "**no potential for compromise of the Cilium stack**"; eBPF programs: None | Workload section | Any pod → agent crash/RCE via DNS proxy, L7 proxy, or BPF parsing (our A) |
| MITM & network attacker: agent, config, eBPF programs all **None** | MITM/Network sections | Crafted packets from the node network that crash the agent, corrupt BPF state, or bypass policy (our C/F) |
| With transparent encryption enabled, MITM can't read/inject | MITM controls | Any way to get plaintext or accepted injected traffic with WireGuard/IPsec on |

### What they don't model at all (our additions)

1. **Namespace-scoped tenant (our B).** They lump every API user into "K8s API Server
   Attacker … regardless of whether the access is full or limited", and only list effects of
   privileged access (Cilium CRDs, CiliumIdentity, exec). They never consider a user who can
   only create *namespaced* objects that Cilium consumes: `CiliumNetworkPolicy`,
   `CiliumEnvoyConfig` (namespaced), Gateway API `HTTPRoute`/`GRPCRoute`/`TLSRoute`,
   `Ingress`, `Service` + `service.cilium.io/*` annotations, pod annotations. Their own
   control is "scope RBAC correctly" — so if a namespace-only permission gives
   cross-namespace or node-level effect, RBAC can't fix it → real vulnerability.
   - Caveat: CEC/CCEC security implications are called out explicitly ("review the L7
     traffic management docs"), so CEC-based escalation may be judged as documented. **HTTPRoute,
     Ingress and Service annotations are the better B targets** — app teams routinely get
     those, and the model doesn't mention them.
2. **External / north-south attacker (our F).** Their network attacker sits on the same
   IP network as the nodes. Nothing covers internet traffic arriving via
   LoadBalancer/NodePort, Cilium Ingress/Gateway as an edge proxy, or the
   `healthCheckNodePort` health servers that cloud LBs probe.
3. **Supply chain / CI (our E).** Explicitly excluded ("does not consider supply-chain
   attacks such as a malicious contributor"), yet `SECURITY.md` puts CI→release-artifact
   compromise in scope. An outsider-triggered workflow (fork PR, issue comment) reaching
   release or signing credentials is neither "malicious contributor" nor modelled.
4. **Malicious DNS → crash/RCE.** They accept that malicious DNS can *influence toFQDNs
   IPs* (so poisoning is out of scope), but don't consider malformed DNS responses
   attacking the proxy itself.

### What they have that we didn't (now noted; mostly by-design / low value)

- Root-equivalent host, `kubectl exec` into Cilium, Cilium-CRD write access → by design.
- KV-store (etcd) attacker → needs etcd creds first; identity spoofing is accepted.
- Hubble data attacker → relies on user network policy/TLS; accepted.
- Cluster Mesh: "all connected clusters form a single trust domain" → **cross-cluster
  impersonation is out of scope**; drop that from our C.

### Already-accepted (don't report these)

IPsec cluster-wide PSK; DNS servers influencing toFQDNs; hostNetwork pods bypassing pod
policy; Hubble metrics leakage when exposed; mass CiliumIdentity creation DoS by
CRD-privileged users; spoofing pod traffic without encryption.

## Leads already seen

| Finding | Area | Status |
|---|---|---|
| `standalone-dns-proxy/pkg/lookup/lookup.go:89` (Critical SAST) | A / F | Not yet triaged |
| `pkg/datapath/loader/compile.go:204` (Critical SAST, BPF compiler execution) | D / B sink | Not yet triaged: only matters if attacker-controlled input reaches it |
