# Contributing

Thanks for helping. Bug reports, fixes, new endpoint paths and small features are
all welcome; for anything large, open an issue first so the approach can be agreed
before you build it.

## Getting set up

See [Development](../README.md#development) in the README for building and
testing the CLI, the dashboard and the container.

## Pull requests

- Keep each pull request to one change.
- Run `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and `cargo test`,
  and add tests for new behavior.
- If you changed `ui/`, run `npm run build` there to type-check it.
- Update the README when behavior or flags change.
- Write commit messages as `<type>(<scope>): <summary>`, for example
  `fix(scanner): resolve IPv6 hosts`.

## Keep it read-only

portscan only makes TCP connections and HTTP `GET` requests. Changes that write,
log in, submit or exploit anything on a target won't be merged.
