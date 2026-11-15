# hemeo

Rust CLI for encrypted clipboard transfer with explicit receiver approval.

- `server` queues content submitted by `send`.
- `client` receives offers; `accept` copies them locally.
- Defaults to Wayland's `wl-paste`/`wl-copy`; custom shell commands are supported.

See `README.md` for usage and protocol details.
