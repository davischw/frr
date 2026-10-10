# GitHub Workflows

## stale.yml - Mark stale issues and PRs

Runs daily at 01:30 UTC (and can be started manually from the Actions tab)
using [actions/stale](https://github.com/actions/stale).

- Open issues and pull requests with no activity for **120 days** get the
  `stale` label.
- Any new activity (comment, push, update) removes the `stale` label again.
- No comment is posted and nothing is ever closed automatically.

The 120-day threshold is set by `days-before-stale` in `stale.yml`.
