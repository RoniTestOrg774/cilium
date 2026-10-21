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

Not included: an area E (CI/workflow) rule. That track was intentionally set
aside, see the decision log in [../process.md](../process.md).
