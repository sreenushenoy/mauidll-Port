# Contributing

Contributions are welcome. Please open an issue to discuss significant changes
before submitting a pull request.

## Development

`mauidll` is a single self-contained Crystal program with no external
dependencies.

```sh
crystal build --release mauidll.cr -o mauidll
crystal tool format --check mauidll.cr
```

It was developed and tested with Crystal 1.20.x.

## Pull requests

- Keep changes focused on a single concern
- Run `crystal tool format` before committing
- Describe what you tested against (MAUI version, ABI, store format)

## Security issues

Do not open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md).
