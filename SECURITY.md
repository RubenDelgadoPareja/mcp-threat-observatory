# Security policy

## Reporting a vulnerability in this tool

Do not open a public issue.

Use GitHub's private vulnerability reporting for this repository
(Security → Report a vulnerability), or contact the maintainer at the address in
`package.json`.

Include: affected version, a minimal reproduction, and the impact you believe it
has. If the issue could cause the collector to contact unintended hosts, send
data somewhere unexpected, or store credentials it should not, say so explicitly
— those are the highest-severity classes for this project.

**Response target:** acknowledgement within 5 working days, assessment within 10.

There is no bug bounty.

## Scope

In scope:

- The collector contacting a host other than the authorised target
- Credential or token leakage in snapshots, logs or reports
- Path or command injection in the CLI
- Incorrect integrity claims (a digest or fingerprint that does not match the
  artifact it describes)
- A check that can be trivially made to produce a false accusation

Out of scope:

- Findings produced by the checks themselves. AUTH-001 firing on a public server
  is the tool working, not a vulnerability.
- Rate limiting that is too slow to be convenient.
- The absence of a check you would like to see. Open a feature request.

## Safe harbour

Good-faith research on this collector, following this policy, will not be
pursued. Do not test against infrastructure you do not own.
