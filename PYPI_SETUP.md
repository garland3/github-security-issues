# PyPI Trusted Publisher Setup

This project uses [trusted publishers](https://docs.pypi.org/trusted-publishers/) (OIDC) so GitHub Actions can publish to PyPI without storing API tokens.

## Steps

### 1. Create a PyPI account

Go to https://pypi.org/account/register/ and create an account if you don't have one.

### 2. Add a pending trusted publisher on PyPI

Go to https://pypi.org/manage/account/publishing/ and fill in:

| Field | Value |
|---|---|
| PyPI project name | `ghsec` |
| Owner | `garland3` |
| Repository name | `github-security-issues` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

Click **Add**.

### 3. Create the `pypi` environment in GitHub

1. Go to https://github.com/garland3/github-security-issues/settings/environments
2. Click **New environment**
3. Name it `pypi`
4. (Optional) Add protection rules like required reviewers if you want manual approval before each publish

### 4. Push to `main`

Every push to `main` will now:
1. Build the sdist and wheel
2. Publish to PyPI via trusted publishing

### Troubleshooting

- **"project does not exist"** — Make sure the pending publisher was added *before* the first publish attempt. PyPI will auto-create the project on the first successful upload.
- **"OIDC token exchange failed"** — Verify the environment name in the workflow (`pypi`) matches exactly what you entered on PyPI.
- **Version conflict** — PyPI rejects uploads with a version that already exists. Bump the version in `pyproject.toml` before pushing.
