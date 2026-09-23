# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in `mauidll`, please report
it privately rather than opening a public issue.

Use GitHub's [private vulnerability reporting](https://github.com/BishopFox/mauidll/security/advisories/new)
to submit a report. Include:

- A description of the issue and its impact
- Steps to reproduce
- Any relevant versions, logs, or sample input

We will acknowledge your report and keep you updated on remediation progress.

## Scope

`mauidll` is an offensive security research tool that parses untrusted binary
input. It is intended to be run against files you are authorized to analyze, in
an environment you control. Crashes or memory issues triggered by malformed input
are in scope; use of the tool against systems you do not have permission to test
is not.
