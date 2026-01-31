# Contributing

Thanks for your interest in contributing!

## Getting started

- **Fork** the repo and create your branch from `master`.
- Use **clear commit messages** and keep changes focused.
- Update or add **tests** for behavior changes.

## Development

- Go version: use the version declared in `go.mod`.
- Format code:
  - `make fmt`
- Lint:
  - `make lint`

## Tests

> [!IMPORTANT]
> Running unit tests requires **both** a local **nmap** installation **and Docker** available on your machine.

Run tests with:

- `make test`

## Pull requests

- Describe the **what** and **why**.
- Link related issues if applicable.
- Ensure CI passes.
