## Pull Request Checklist

Before submitting this pull request, please ensure:

- [ ] Code builds cleanly with `/W4 /WX` with zero compiler warnings.
- [ ] No em dashes (`\u2014`) or en dashes (`\u2013`) are introduced. Use ASCII hyphens `-`.
- [ ] New MCP tools include complete docstrings, parameter descriptions, and return type hints.
- [ ] If native exports are added, they are properly registered in `pipe_server.cpp` and `server.py`.
- [ ] Tool counts match verified regression targets (234 tools).
- [ ] PR description clearly explains what changed, why, and how it was tested.

## Summary of Changes

<!-- Describe what changes are being made and why -->

## Testing Conducted

<!-- Describe how this was tested (live x64dbg, unit tests, mock tests) -->
