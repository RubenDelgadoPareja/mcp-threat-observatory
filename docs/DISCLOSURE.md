# Disclosure policy

Applies to findings about **third-party servers** produced by this collector or
by anyone using it. Findings about your own infrastructure need no disclosure.

## 1. Default position

Do not publish a named finding before the operator has been notified, unless the
information is already public or the operator has consented.

A passive record is not proof of compromise. Publishing it as if it were turns a
measurement into an accusation.

## 2. Timeline

| Day | Action |
| --- | --- |
| 0 | Notify the operator through a public security contact, or the registry if none exists |
| 0 | Record the notification in the research log (date, channel, message digest) |
| 7 | Follow up if there is no acknowledgement |
| 30 | Target for a fix, or for a public statement of intent |
| 90 | Publishable by default, with the response status noted |

The clock is paused if the operator is actively remediating and communicating.

## 3. Escalation

If the operator cannot be reached, escalate in this order:

1. The registry or marketplace that lists the server (npm, PyPI, official MCP
   registry, directory operator).
2. The hosting provider, for a server that is clearly abandoned or
   impersonating another project.
3. A national CERT, for anything that could cause harm beyond the operator's own
   users.

## 4. What gets published

| Published | Not published |
| --- | --- |
| The check that fired and why | Credentials, tokens, personal data |
| The date of observation | Raw response bodies that identify customers |
| Aggregate counts and distributions | Named lists of individually exposed servers |
| The operator's response status | Speculation about intent or actors |
| Methodology and limitations | Claims stronger than the sample supports |

Naming a specific server is acceptable when: the operator consented, the finding
is already public, or the server is malicious infrastructure and naming it
protects users. The last case requires evidence beyond a passive handshake.

## 5. Message template

```
Subject: Passive security observation of <server name> (<host>), <date>

Hello,

I run a passive collector that performs an ordinary MCP client handshake
(initialize, tools/list, resources/list, prompts/list) and never invokes a tool.
On <date> I observed the following on <host>:

  - <check id>: <one sentence, observation only>

I am not claiming this is exploitable or intentional. I am reporting it because
<reason: it breaks client discovery / it exposes a destructive tool without
authentication / ...>.

Suggested remediation: <one sentence, with a spec reference>.

I intend to include this in <aggregate research / a public write-up> after
<date>. If you would like a different timeline, or if this is expected
behaviour, tell me and I will record your response.

Regards,
<name>, <contact>
```

## 6. Corrections

If a finding turns out to be wrong:

1. Correct the record and the derived dataset.
2. Publish the correction with the same prominence as the original.
3. Note what the false positive was, and what changed in the check.

An unreported correction is worse than the original error: it destroys the
provenance the whole project exists to provide.

## 7. Log

Keep a disclosure log alongside the snapshots. One line per finding:

```json
{"check":"AUTH-003","target":"...","first_seen":"...","notified":"...","channel":"...","response":"...","published":"..."}
```
