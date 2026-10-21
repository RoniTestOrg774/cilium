# Custom Bearer rules, draft

Draft custom Bearer rules encoding hypotheses from [../threat-model.md](../threat-model.md).
These are a first pass, not yet validated against Bearer's actual rule schema
or run against the codebase. Check pattern syntax and the `detection` filter
names against `bearer rules` scaffolding or Bearer's own docs before relying
on a result, a wrong field name is more likely to silently match nothing than
to error.

- `namespace-field-to-envoy-config.yml` — area B: a namespace-scoped resource
  field (HTTPRoute, Ingress, Service, annotations) reaching Envoy config
  construction without a namespace check.
- `unescaped-string-into-envoy-route-match.yml` — area B: a user-controlled
  string used in Envoy regex/path/header match construction without escaping.
- `dns-msg-index-without-length-check.yml` — area A/F: DNS message indexing or
  slicing without a prior length check, reachable from the DNS proxy.
- `ipv6-parity-in-dns-handling.yml` — area A/F: a check applied to IPv4 (A
  record) data with no equivalent check for IPv6 (AAAA record) data, so a
  dual-stack bypass is possible.
- `fqdn-case-sensitive-match.yml` — area A/F: FQDN policy matching a DNS name
  without case normalization first, since DNS names are case-insensitive.
- `fqdn-subdomain-boundary-confusion.yml` — area A/F: FQDN policy using a
  suffix or substring check without a label boundary, so
  "evilexample.com" or "example.com.attacker.net" can be confused with
  "example.com".

Not included: an area E (CI/workflow) rule. That track was intentionally set
aside, see the decision log in [../process.md](../process.md).
