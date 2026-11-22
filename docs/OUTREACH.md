# Consented pilot: outreach and rules of engagement

The project's remaining gap is not code: it is a real finding, obtained with
permission. This document is the process for getting one without burning
credibility or crossing a line.

## Rules of engagement

1. **Written permission first.** An email, a DM, a GitHub issue where the
   maintainer agrees. Keep it. "It was public" is not permission.
2. **Never name a project without consent.** Not in a blog post, not in a
   commit message, not in a talk.
3. **Draft before publish.** The maintainer sees the report before anyone else
   and gets 30 days to respond.
4. **One follow-up, then silence.** No chasing. A second unanswered message is
   the last one.
5. **Raw artefacts stay private.** Publish the report and aggregate counts, not
   the environment dump.
6. **A real vulnerability stops the pilot.** If a run reveals an exposed secret,
   an authentication bypass or remote code execution, stop and follow
   [DISCLOSURE.md](DISCLOSURE.md) instead. That is a different process with a
   different clock.
7. **No exploitation, ever.** The behavioural run never attempts to prove impact
   beyond what the sandbox records.

## Choosing the five

Send five, expect two replies, expect one yes. Pick for response rate, not
prestige.

| Signal | Good | Avoid |
| --- | --- | --- |
| Activity | Commits in the last 90 days | Abandoned |
| Surface | Tools that read files, run commands or make requests | Docs-only wrappers |
| Contactability | `SECURITY.md`, package author email, active maintainer | Org with no public contact |
| Size | One to three maintainers | A platform team with a legal queue |
| Attitude | Mentions security, has an advisory process | Known hostile to researchers |

Start with servers you already use. A maintainer who recognises your GitHub
handle replies more often than a stranger.

## The message

Short, specific, and easy to refuse. The ask is small and the benefit is theirs.

```text
Subject: Permission to include <project> in a consented MCP security pilot

Hi <name>,

I maintain mcp-threat-observatory (https://github.com/RubenDelgadoPareja/mcp-threat-observatory),
an open-source collector that records what MCP servers advertise and what they do
at runtime. Every finding is graded as observed or inferred, with its limitations
stated rather than implied.

I would like to include <project> in a small consented pilot, with your review
before anything is published.

What it involves:

  1. A passive handshake against the endpoint, or a local stdio run. No
     credentials, no tool invocation.
  2. One sandboxed behavioural run: network namespace with no route, temporary
     HOME, synthetic canary credentials, every tool invoked once. Nothing leaves
     the sandbox and no real credential is ever used.
  3. A short report: what was observed, what it may mean, and what I could not see.

What I will not do: exploit anything, touch real user data, publish a payload, or
name <project> without your agreement. You get the draft first, 30 days to
respond, and your response is published alongside the findings.

If you would rather not grant access, there is a zero-trust alternative: run it
yourself and send me the output, or don't. It takes about a minute:

  git clone https://github.com/RubenDelgadoPareja/mcp-threat-observatory
  cd mcp-threat-observatory && npm install && npm run build
  npx github:RubenDelgadoPareja/mcp-threat-observatory behaviour --authorized -- <your command>

Either way: no pressure, and no follow-up if you would rather not.

Thanks for the work on <project>.

<your name>
<repo> · <disclosure policy>
```

### Why this shape works

- **It names the scope before the ask.** The maintainer can picture the work.
- **It offers a zero-trust path.** That is the difference between a reply and a
  report button.
- **It gives them the publication veto.** Permission is easier to grant when it
  is revocable.
- **It states the limit of the evidence.** "What I could not see" is the phrase
  that separates this from a scanner pitch.

### Voice

| Say | Do not say |
| --- | --- |
| "I maintain mcp-threat-observatory" | "I am a security researcher" |
| "I would like to include your server" | "I am auditing your server" |
| "Here is what I observed and could not see" | "I found vulnerabilities" |
| "No pressure, no follow-up" | "Looking forward to your prompt response" |

## Handling replies

| Reply | Response |
| --- | --- |
| Yes | Thank them, confirm scope in one line, run within a week |
| Yes, but no publication | Run, send the report privately, do not publish |
| "We will fix it first" | Wait, re-run after the fix, publish with the fix noted |
| No | Thank them, log it, move on |
| Silence after 30 days | Publish aggregate-only: "N servers assessed, M declined, 0 named" |
| A vulnerability surfaces | Stop. Follow DISCLOSURE.md. The pilot is over. |

## Pilot plan

| Week | Work | Done when |
| --- | --- | --- |
| 0 | Pick five, find contacts, record them | Five names with a channel each |
| 1 | Send five messages | Five sent, tracked |
| 2 | For each yes: passive record, then behavioural run | One artefact pair per server |
| 3 | Write the report; send the draft | Draft acknowledged |
| 4 | Publish with the response | One public report URL |

One server end to end is enough for the portfolio. Five identical reports are
not better than one careful one.

## What gets published

| Published | Private |
| --- | --- |
| The check that fired and why | Raw behaviour JSONL |
| The date and the isolation used | Canary values |
| The maintainer's response | Any payload bytes |
| Aggregate counts across the pilot | Contact details |
| Methodology and limitations | The list of projects that declined |

A refusal is not a finding. Publishing "these five declined" invites retaliation
against the next researcher.

## Tracker

Keep this **outside the public repository**. A public list of targets reads as
pressure, even when it is not.

```markdown
| Project | Channel | Sent | Reply | Status | Run | Report | Published |
| --- | --- | --- | --- | --- | --- | --- | --- |
| example-mcp | email (package metadata) | 2026-11-25 | yes | analysed | 2026-11-27 | /tmp/draft.md | — |
```

## The sentence this buys you

> "I ran a consented assessment of <project> with its maintainer, published the
> findings with their response, and they changed <thing>."

That sentence is worth more than another thousand lines of code, and it is the
one thing a portfolio cannot fake.
