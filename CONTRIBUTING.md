# Contributing

**pcaplens** — pcap / pcapng parser with a CLI and an MCP server — is small on purpose: hand-written parsers, deterministic rules, no dependencies. Contributions that keep it that way are welcome.

## Setup

```bash
git clone https://github.com/xuange-hu/pcaplens
cd pcaplens
pip install -e ".[mcp]" pytest ruff
pytest                 # 70 tests
ruff check src tests
```

No `pip install` is needed to run the tests after a clone — the root
`conftest.py` puts `src/` on `sys.path`.

## Rules and where they live

`src/pcaplens/pcap.py` (format), `src/pcaplens/dissect.py` (protocols), `src/pcaplens/aggregate.py` (conversations).

## Adding a rule

1. **A synthesised capture** built by `src/pcaplens/synth.py` — never a real capture, and never a binary committed without a generator.
2. **The dissector** in `src/pcaplens/dissect.py`, returning offsets rather than prose.
3. **A round-trip test**: what the parser reports must be checkable against the bytes at the offset it reports.

Then update the rule table and the test-count badge in `README.md`. CI warns
when the badge and pytest disagree.

## Rules of the road

- **Zero dependencies in `src/` outside `mcp_server.py`.** `tests/test_packaging.py`
  fails on an optional import leaking into a required path.
- **No network access.** Not in the scanner, not in the tests. Tests that need
  a file write it to `tmp_path`.
- **Every finding carries a location and its source text.** A report that says
  "something is wrong" without saying where gets closed and forgotten.
- **`absent` and `empty` are different.** Decide what the explicit empty form
  means before adding a rule that fires on a missing field.
- **Line numbers come from the parser.** Do not compute them in the rule.

## Commit and PR

- One logical change per commit.
- CI runs on 3.10–3.13 across Ubuntu and Windows. A test that passes only on
  your machine will be caught there, so run `pytest` before pushing.
