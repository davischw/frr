# GitHub Workflows

## base-branch-label.yml - Label PRs with their target branch

Runs when a pull request is opened or reopened and adds a label named after
the branch the PR targets (e.g. a PR against `frr-dpd-8.4` gets the
`frr-dpd-8.4` label). This makes it easy to filter PRs by target branch.

For branches starting with `frr-dpd-x.y`, the `x.y` version is added as an
additional label:

| Target branch              | Labels                               |
|----------------------------|--------------------------------------|
| `frr-dpd-8.4`              | `frr-dpd-8.4`, `8.4`                 |
| `frr-dpd-8.4-devel_cosmos` | `frr-dpd-8.4-devel_cosmos`, `8.4`    |
| `master`                   | `master`                             |

- The label is created automatically if it doesn't exist yet.
- Changing the base branch of an existing PR does not update the label.

## stale.yml - Mark stale issues and PRs

Runs daily at 01:30 UTC (and can be started manually from the Actions tab)
using [actions/stale](https://github.com/actions/stale).

- Open issues and pull requests with no activity for **120 days** get the
  `stale` label.
- Any new activity (comment, push, update) removes the `stale` label again.
- No comment is posted and nothing is ever closed automatically.

The 120-day threshold is set by `days-before-stale` in `stale.yml`.
