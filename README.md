# hemeo — hear me out

Send clipboard content over encrypted TCP, with explicit approval on the receiving machine.
Defaults to `wl-paste` in `send` and `wl-copy` in `accept` (`wl-clipboard`);
custom commands can replace either without requiring Wayland.
Networking uses Rust's standard library; no SSH is involved.

## Quick start

Run in a Wayland session with `wl-clipboard` installed on both machines.
Build on both machines with `cargo build --release`; the binary is
`./target/release/hemeo`.

1. **Sender:** start the server and leave it running:
   ```sh
   ./target/release/hemeo server --bind 0.0.0.0:7331 --secret 'YOUR-LONG-RANDOM-SECRET'
   ```
2. **Receiver:** replace `SENDER_IP` with the sender's IP, use the same secret,
   and leave the client running:
   ```sh
   ./target/release/hemeo client --server SENDER_IP:7331 --secret 'YOUR-LONG-RANDOM-SECRET'
   ```
3. **Sender, another terminal:** copy something, then trigger a transfer:
   ```sh
   ./target/release/hemeo send
   ```
4. **Receiver, another terminal:** approve the offer to update your clipboard:
   ```sh
   ./target/release/hemeo accept
   ```

Repeat steps 3–4 for each transfer. Allow inbound TCP port `7331` on the sender.
Optional notification hooks and other settings are described below; examples
below assume `hemeo` is on your `PATH`.

## Usage

Build with `cargo build --release`.

Start the receiving client (it retries connections automatically):

```sh
hemeo client --server 192.168.1.10:7331 --secret 'your-shared-secret' \
  --on-request 'notify-send "Clipboard offered" "Run hemeo accept to copy from $HEMEO_SERVER"' \
  --on-accept 'notify-send "Clipboard received" "Copied from $HEMEO_SERVER"'
```

Add `--tray` to the client to show a system tray icon:

```sh
hemeo client --server 192.168.1.10:7331 --secret 'your-shared-secret' --tray
```

The placeholder icon is gray while idle and amber while an offer is pending.
Open its menu and choose **Accept clipboard** to copy using `wl-copy`.
For custom put commands, continue using `hemeo accept --put-command ...`;
the icon updates either way. Failed copies leave the offer pending.
This requires a session D-Bus and a StatusNotifierItem-compatible tray host
(for example, Waybar with its `tray` module enabled). Sway alone does not
provide a tray host.

On the sending machine, start the persistent server:

```sh
hemeo server --bind 0.0.0.0:7331 --secret 'your-shared-secret'
```

To offer the current clipboard, run on the sending machine:

```sh
hemeo send
```

The send command captures the current clipboard and returns immediately after
submitting it, without waiting for acceptance. The server waits for an
authenticated client, transfers the offer, then waits for approval. Both server
and client stay running; run `hemeo send` again for each new transfer.
Only one offer is handled at a time; additional sends report that the server is
busy. If no client is available, the offer waits for one. Transfer failures are
logged by the server; run `hemeo send` again to retry.

On the receiving machine, approve the pending offer:

```sh
hemeo accept
```

Until acceptance, the data is held in memory and the local clipboard is unchanged.
Failed put commands leave the offer pending so acceptance can be retried.
The completion hook fires only after copying succeeds.

Hooks are optional shell commands run through `sh -c`, with `HEMEO_SERVER`,
`HEMEO_MIME_TYPE`, and `HEMEO_BYTES` environment variables. They receive no clipboard
content on stdin. Keep hooks short-lived (for example, `notify-send` or a script).
Hook failure is logged but does not reject or undo the clipboard operation.

Control sockets are mode `0600`. The client/accept socket defaults to
`$XDG_RUNTIME_DIR/hemeo.sock`; the server/send socket defaults to
`$XDG_RUNTIME_DIR/hemeo-server.sock`, so both can run on the same machine.
Use `--socket /private/directory/custom.sock` on both commands in the relevant
pair to override it. Use a directory only your user can access. On startup,
each listener automatically removes a stale control socket. It refuses to replace a socket
belonging to a running listener or delete a non-socket file.

The default MIME type is `text/plain`. To transfer an image, use
`hemeo send --mime-type image/png`.
The accept command passes the received MIME type to `wl-copy`. Transfers are limited to
64 MiB. `wl-paste --no-newline` avoids adding a newline. Set `WAYLAND_DISPLAY` in
the environment of `send` or `accept` if needed (for example, `wayland-1`).

## Custom content commands

Set `--get-command` on `send` to choose a shell command whose stdout becomes
the content for that transfer. Set `--put-command` on `accept` to
choose a shell command that receives the content on stdin when you run
`hemeo accept`.

For example, send `asdf` and print it in the accepting terminal:

```sh
hemeo server --bind 0.0.0.0:7331 --secret 'your-shared-secret'
hemeo client --server SENDER_IP:7331 --secret 'your-shared-secret'
```

Run the server and client on their respective machines, then run
`hemeo send --get-command 'echo asdf'` on the sender and
`hemeo accept --put-command 'cat'` on the receiver. The output appears in the
terminal running `hemeo accept`; it can also be redirected to a file.

Commands run through `sh -c`. Content is passed as raw bytes, never substituted
into shell code: there is no `{}` placeholder. `cat` is the stdin equivalent of
printing the received content; `cat > /path/to/file` saves it instead. This
preserves binary data, quotes, and newlines without executing received text.
`echo asdf` includes a newline; use `printf %s asdf` to omit it.

Both commands receive `HEMEO_MIME_TYPE`. The put command also receives
`HEMEO_SERVER` and `HEMEO_BYTES`. Defaults are:

- Get: `wl-paste --no-newline --type "$HEMEO_MIME_TYPE"`
- Put: `wl-copy --type "$HEMEO_MIME_TYPE"`

Only get-command stdout is captured; stderr remains visible. The put command's
stdout and stderr are inherited from `accept`. Commands must finish with exit
status zero for the operation to succeed. A failed get command prevents sending;
a failed put command leaves the offer pending and does not fire `--on-accept`.
Only configure commands you trust, and keep them short-lived.

## Security

Clipboard content, MIME type, handshake proofs, and acceptance acknowledgments
are encrypted and authenticated with AES-256-GCM. The shared secret is never
transmitted. Both peers prove knowledge of the secret before clipboard transfer.
This protocol is incompatible with older, unencrypted versions of hemeo.

Each connection uses 32 fresh random bytes from each peer. Argon2id (v19,
19 MiB memory, 2 iterations, parallelism 1) derives a 256-bit session key from
`--secret`, using the client randomness followed by the server randomness as
its salt. Each of the five protocol messages uses a distinct 96-bit nonce
(numbered 0 through 4), with the protocol identifier authenticated as associated
data. A session key is used for only one transfer; fresh contributions from both
peers prevent recorded sessions from being replayed to either peer.

Use a strong, unique, randomly generated secret: captured handshakes permit
offline password guessing despite Argon2's cost. This shared-secret protocol
does not provide forward secrecy: learning the secret later allows decryption
of recorded traffic. Traffic sizes and timing remain visible, and connections
can still be blocked or disrupted. Anyone with the secret can impersonate either
peer. For public-facing deployments, prefer an established secure tunnel as well.

Secrets supplied through flags may appear in shell history and process listings.
The TCP listener defaults to loopback; explicitly set `--bind` to expose it to
another machine. Never accept an unexpected offer.
