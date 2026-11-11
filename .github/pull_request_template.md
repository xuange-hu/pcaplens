## What / 改了什么

<!-- One paragraph. Link the issue if there is one: Closes #123 -->

## Surfaces touched / 涉及入口

- [ ] Core library / engine
- [ ] CLI
- [ ] MCP server (new or changed tools?)
- [ ] Rules / checks
- [ ] Docs only

## Checklist / 提交前检查

- [ ] `pytest -q` passes (count is in the README tests badge)
- [ ] `ruff check src tests` passes
- [ ] New behavior is covered by at least one test
- [ ] New MCP tool has a docstring (agents read it to decide when to call)
- [ ] Optional third-party imports are guarded (`try/except ImportError`)
- [ ] README / docs updated if the surface changed
- [ ] No credentials, tokens or personal paths in the diff

## How to verify / 怎么验证

```bash
# commands a reviewer can run
pcaplens summary capture.pcap
```
