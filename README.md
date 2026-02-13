# Release Notes

Automated release notes generation tooling for PCS Core.

## Tools

### `generate_pr_release_notes.rb`

Generates release notes for a single pull request. Loads prompt templates from Confluence for consistent formatting across PR and deployment release notes. Designed to run in GitHub Actions CI with no external gem dependencies (Ruby stdlib only).

Used by the GitHub Actions workflow in `pcs_core` to generate, approve, and gate merging of PRs based on reviewed release notes.

**Usage:**

```bash
ruby generate_pr_release_notes.rb --pr 123 --base origin/main --head pr_head --verbose
```

| Flag | Required | Description |
|------|----------|-------------|
| `--pr NUMBER` | Yes | Pull request number |
| `--base REF` | Yes | Base git reference (e.g., `origin/main`) |
| `--head REF` | Yes | Head git reference (e.g., `pr_head`) |
| `--verbose` | No | Print progress logs to stderr |

### `generate_release_notes.rb`

Generates deployment-level release notes by comparing two git references (e.g., `production` vs `main`). Publishes structured summaries to Confluence with LLM-generated sections.

**Usage:**

```bash
ruby generate_release_notes.rb --base production --compare main --verbose
```

| Flag | Required | Description |
|------|----------|-------------|
| `--base REF` | No | Base reference (default: `production`) |
| `--compare REF` | No | Compare reference (default: `main`) |
| `--output DIR` | No | Output directory (default: `.`) |
| `--verbose` | No | Verbose output |

### `confluence_client.rb`

Helper class for Confluence API interactions. Used by `generate_release_notes.rb` to fetch prompt configuration and publish pages.

## Environment Variables

All environment variables use the `RN_` prefix to avoid conflicts with other tools.

### Required (PR release notes)

| Variable | Description |
|----------|-------------|
| `RN_ANTHROPIC_API_KEY` | Anthropic API key for Claude LLM |
| `RN_CONFLUENCE_BASE_URL` | Confluence instance URL (for loading prompt templates) |
| `RN_ATLASSIAN_API_TOKEN` | Atlassian API token (for Confluence) |
| `RN_JIRA_EMAIL` | Atlassian account email |

### Required (deployment release notes)

| Variable | Description |
|----------|-------------|
| `RN_ANTHROPIC_API_KEY` | Anthropic API key for Claude LLM |
| `RN_JIRA_BASE_URL` | Jira instance URL (e.g., `https://yourcompany.atlassian.net`) |
| `RN_JIRA_CLOUD_ID` | Atlassian Cloud ID |
| `RN_JIRA_EMAIL` | Atlassian account email |
| `RN_ATLASSIAN_API_TOKEN` | Atlassian API token (Jira and Confluence) |
| `RN_CONFLUENCE_BASE_URL` | Confluence instance URL |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `RN_GH_ACCESS_TOKEN` | GitHub token for fetching PR details | — |
| `RN_ANTHROPIC_MODEL` | Claude model to use | `claude-haiku-4-5` |

## GitHub Actions Integration

The `pcs_core` repository contains a workflow (`.github/workflows/release-notes.yml`) that uses this repo via slash commands on PRs:

| Command | Effect |
|---------|--------|
| `/release-notes-generate` | Generates release notes, posts as PR comment, sets `release-notes-approved` status to pending |
| `/release-notes-approve` | Sets commit status to success (unblocks merge) |
| `/release-notes-revoke` | Sets commit status back to pending (re-blocks merge) |

### Setup

1. Add required secrets to the `pcs_core` repository (see environment variables above).
2. Add a branch protection rule on `main` requiring the `release-notes-approved` status check to pass.
