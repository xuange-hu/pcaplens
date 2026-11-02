# Security policy

## Scope

**pcaplens** — pcap / pcapng parser with a CLI and an MCP server — is a static analysis tool: it reads **`.pcap` and `.pcapng` capture files** and prints a report.
The security questions that apply to it are the ones that apply to any tool
that parses untrusted input.

Supported: the current release.

## What this tool does with your files

Nothing leaves your machine. There is no network client in the scanning path:
the tool opens the files you point it at, parses them, and writes a report.
It never writes to the files it reads.

## Reporting a vulnerability in pcaplens

Use [GitHub private vulnerability reporting](https://github.com/xuange-hu/pcaplens/security/advisories)
on the Security tab. If private reporting is unavailable to you, open an issue
marked `security`.

Include:

1. the version (`pcaplens --version`);
2. the input that triggers it — the actual file is preferred over a description;
3. what you expected and what happened.

For a parse failure, the smallest input that reproduces it is the whole report.

## What counts as a vulnerability here

- **A crash on a malformed capture.** Captures are attacker-influenced input in the environment this is built for; a traceback is not an acceptable answer to a corrupt file.
- **Unbounded allocation.** A header that claims a huge packet or record length must be rejected, not believed.
- **An off-by-one that reports the wrong byte offset.** The tool's whole contract is that every claim can be checked against the bytes; a wrong offset is worse than no output.
- **A path that escapes the directory it was pointed at.**

## What does not count

- A rule firing on input you consider correct. That is a false positive: open
  an issue with the sample and it gets a regression test.
- A rule you want added. Open an issue or a PR.

## Timing

I triage within a week and will confirm receipt. If a fix needs to sit in a
branch for a while, the advisory goes out when the fix lands, not before.
