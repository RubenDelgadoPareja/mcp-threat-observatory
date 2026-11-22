# Ethics and authorisation

This tool sends network requests. "Passive" describes the method, not the
permission. This document states the rules the collector enforces and the rules
an operator is expected to follow.

## 1. Authorisation

You may only observe a server that:

- you operate, or
- you have written permission from its operator to test.

An entry in a public registry is **not** permission. A server being reachable is
**not** permission.

The CLI enforces this with a consent gate: it refuses to run without
`--authorized` (or `MCPOBS_AUTHORIZED=1`), and prints the distinction between
"allowed" and "not allowed" when it refuses. A convenience flag, not a legal
shield — the responsibility is the operator's.

## 2. What "passive" means precisely

This section applies to `mcpobs scan`. Behavioural collection is a separate mode
with its own rules; see [2.1](#21-behavioural-mode).

The passive collector may send only these methods:

```
initialize
notifications/initialized
tools/list
resources/list
prompts/list
```

plus unauthenticated `GET` requests to `/.well-known/oauth-protected-resource`
and the URL advertised in a `WWW-Authenticate` challenge.

The passive collector must never:

- call a tool, or send `tools/call`;
- send prompts, sampling requests, or completions;
- submit credentials, tokens, or guessed API keys;
- enumerate paths, fuzz parameters, or attempt authentication bypass;
- follow redirects away from the target host;
- retry aggressively or distribute requests to evade rate limits.

## 2.1 Behavioural mode

`mcpobs behaviour` executes a server, so it is not passive and the rules above do
not apply. It has its own contract:

| Control | Behaviour |
| --- | --- |
| Consent | Refuses without `--authorized` |
| Network | `unshare -rn` (no route, no DNS); refuses to run if unavailable, unless `--allow-unisolated` |
| Home directory | Temporary, seeded with canaries; the real `HOME` is never exposed |
| Environment | Rebuilt from scratch: no inherited tokens or cloud credentials |
| Tool calls | One per tool, with schema-generated arguments |
| Scope | Code you wrote, or are authorised to execute |

The observation hook is **not** a security boundary: native code can bypass it.
The network namespace is the boundary, and it covers the network only. This is
stated in every artefact's `limitations`.

Behavioural collection must never:

- run a package you have not authored or been authorised to execute;
- run against a production account or with real credentials;
- be used to obtain a third party's data;
- publish a payload or a victim's content.

## 3. Request hygiene

| Control | Default | Enforced |
| --- | --- | --- |
| Rate limit | 1 request/second/host | Floor of 1, ceiling of 10 |
| Timeout | 15 seconds | Per request |
| User agent | Identifies the collector and contact | Always |
| Credentials in URL | Rejected before any request | Always |
| Non-HTTPS target | Rejected unless loopback | Always |
| Header values stored | Never | Always |
| Body size | 256 KiB cap, digest of full body | Always |

Operators should set `MCPOBS_CONTACT` to a real contact. A record without one is
marked as weaker provenance by the tool itself.

## 4. Data handling

- **Minimise.** Only protocol metadata and bounded body excerpts are stored.
- **Do not publish raw snapshots** without review: response bodies may contain
  personal data, internal hostnames, or customer identifiers even when no
  credential was sent.
- **Retention.** Keep raw snapshots only as long as the research question
  requires. The index is a record of observation, not an archive of content.
- **Aggregation over exposure.** Publish counts, distributions and methodology
  rather than lists of named, individually exposed servers.

## 5. Publishing results

Rules for anything derived from this collector:

1. **No victim naming** without disclosure and consent, unless the finding is
   already public.
2. **No intent attribution.** "This server exposed a destructive tool without
   authentication" is a finding. "This operator is negligent" is not yours to
   conclude.
3. **No aggregate claim stronger than the sample.** "We observed 40 servers" is
   not "40% of the ecosystem".
4. **State the blind spots** in the same document as the numbers, not in an
   appendix.
5. **Correct in public.** If a finding is wrong, publish the correction with the
   same prominence as the original.

## 6. Legal notes

Unauthorised access and unauthorised interception are criminal offences in most
jurisdictions (for example the US CFAA, the UK Computer Misuse Act, and Articles
197 bis and following of the Spanish Criminal Code). A passive handshake is
still an interaction with someone else's system.

If a snapshot contains personal data, GDPR and similar regimes may apply to its
storage and publication, independently of whether the collection was authorised.

This is not legal advice. If you intend to collect at scale, get advice.

## 7. Reporting a problem with this tool

See [SECURITY.md](../SECURITY.md). Do not open a public issue for a
vulnerability in the collector.
