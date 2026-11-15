use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, bail, ensure};
use argon2::Argon2;
use clap::{Parser, Subcommand};

use std::{
    env, fs,
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

const MAX_CLIPBOARD: usize = 64 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
const PROTOCOL: &[u8; 7] = b"hemeo\0\x01";

#[derive(Parser)]
#[command(
    name = "hemeo",
    version,
    about = "Send clipboard content with explicit approval"
)]
struct Cli {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    #[command(about = "Run the clipboard server; trigger transfers with hemeo send")]
    Server {
        #[arg(long, default_value = "127.0.0.1:7331")]
        bind: String,
        #[arg(long)]
        secret: String,
        #[arg(long, default_value = "text/plain")]
        mime_type: String,
        #[arg(
            long,
            default_value = "wl-paste --no-newline --type \"$HEMEO_MIME_TYPE\"",
            help = "Shell command whose stdout supplies the content on each send"
        )]
        get_command: String,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    #[command(about = "Wait for offers; reconnect automatically")]
    Client {
        #[arg(long)]
        server: String,
        #[arg(long)]
        secret: String,
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(
            long,
            default_value = "wl-copy --type \"$HEMEO_MIME_TYPE\"",
            help = "Shell command receiving the content on stdin after acceptance"
        )]
        put_command: String,
        #[arg(long, help = "Shell command to run when an offer arrives")]
        on_request: Option<String>,
        #[arg(long, help = "Shell command to run after copying succeeds")]
        on_accept: Option<String>,
    },
    #[command(about = "Offer the current clipboard through the running server")]
    Send {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    #[command(about = "Copy the pending offer to the local clipboard")]
    Accept {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

struct Pending {
    stream: TcpStream,
    cipher: Aes256Gcm,
    data: Vec<u8>,
    mime_type: String,
    server: String,
}

fn read_frame(
    stream: &mut TcpStream,
    cipher: &Aes256Gcm,
    message: u8,
    limit: usize,
) -> Result<Vec<u8>> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(
        (16..=limit + 16).contains(&length),
        "invalid encrypted frame length"
    );
    let mut data = vec![0; length];
    stream.read_exact(&mut data)?;
    let mut nonce = [0; 12];
    nonce[11] = message;
    cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &data,
                aad: PROTOCOL,
            },
        )
        .map_err(|_| anyhow::anyhow!("authentication failed: wrong secret or tampered message"))
}

fn write_frame(stream: &mut TcpStream, cipher: &Aes256Gcm, message: u8, data: &[u8]) -> Result<()> {
    let mut nonce = [0; 12];
    nonce[11] = message;
    let data = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: data,
                aad: PROTOCOL,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    stream.write_all(&u32::try_from(data.len())?.to_be_bytes())?;
    stream.write_all(&data)?;
    Ok(())
}

fn handshake(stream: &mut TcpStream, secret: &str, server: bool) -> Result<Aes256Gcm> {
    let mut salt = [0; 64];
    let (ours, theirs) = if server {
        (32..64, 0..32)
    } else {
        (0..32, 32..64)
    };
    getrandom::fill(&mut salt[ours.clone()])
        .map_err(|error| anyhow::anyhow!("random generation failed: {error}"))?;
    if !server {
        stream.set_read_timeout(None)?;
    }
    for send in if server { [false, true] } else { [true, false] } {
        if send {
            stream.write_all(PROTOCOL)?;
            stream.write_all(&salt[ours.clone()])?;
        } else {
            let mut protocol = [0; 7];
            stream.read_exact(&mut protocol)?;
            ensure!(&protocol == PROTOCOL, "unsupported protocol");
            stream.read_exact(&mut salt[theirs.clone()])?;
        }
    }
    stream.set_read_timeout(Some(TIMEOUT))?;
    let mut key = [0; 32];
    Argon2::default()
        .hash_password_into(secret.as_bytes(), &salt, &mut key)
        .map_err(|error| anyhow::anyhow!("key derivation failed: {error}"))?;
    let cipher = Aes256Gcm::new(&key.into());
    if server {
        ensure!(
            read_frame(stream, &cipher, 0, 0)?.is_empty(),
            "invalid client proof"
        );
        write_frame(stream, &cipher, 1, b"")?;
    } else {
        write_frame(stream, &cipher, 0, b"")?;
        ensure!(
            read_frame(stream, &cipher, 1, 0)?.is_empty(),
            "invalid server proof"
        );
    }
    Ok(cipher)
}

fn socket_path(socket: Option<PathBuf>, server: bool) -> Result<PathBuf> {
    match socket {
        Some(path) => Ok(path),
        None => Ok(PathBuf::from(
            env::var_os("XDG_RUNTIME_DIR")
                .context("XDG_RUNTIME_DIR is unset; specify --socket in a private directory")?,
        )
        .join(if server {
            "hemeo-server.sock"
        } else {
            "hemeo.sock"
        })),
    }
}

fn control_listener(socket: &std::path::Path) -> Result<UnixListener> {
    let listener = match UnixListener::bind(socket) {
        Ok(listener) => Ok(listener),
        Err(error) if error.kind() == ErrorKind::AddrInUse => {
            match UnixStream::connect(socket) {
                Ok(_) => bail!("listener already running at {}", socket.display()),
                Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
                    ensure!(
                        fs::symlink_metadata(socket)?.file_type().is_socket(),
                        "refusing to remove non-socket file at {}",
                        socket.display()
                    );
                    fs::remove_file(socket)
                        .with_context(|| format!("remove stale socket {}", socket.display()))?;
                }
                Err(error) => return Err(error).context("check existing control socket"),
            }
            UnixListener::bind(socket)
        }
        Err(error) => Err(error),
    }
    .with_context(|| format!("bind {}", socket.display()))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn hook(command: &Option<String>, server: &str, mime_type: &str, bytes: usize) {
    if let Some(command) = command {
        match Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("HEMEO_SERVER", server)
            .env("HEMEO_MIME_TYPE", mime_type)
            .env("HEMEO_BYTES", bytes.to_string())
            .stdin(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => eprintln!("hook exited with {status}"),
            Err(error) => eprintln!("hook failed: {error}"),
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Action::Server {
            bind,
            secret,
            mime_type,
            get_command,
            socket,
        } => {
            ensure!(
                !secret.is_empty() && secret.len() <= 4096,
                "secret must be 1..=4096 bytes"
            );
            ensure!(
                !mime_type.is_empty() && mime_type.len() <= 256,
                "MIME type must be 1..=256 bytes"
            );
            let listener = TcpListener::bind(&bind).context("bind TCP listener")?;
            let socket = socket_path(socket, true)?;
            let control = control_listener(&socket)?;
            let (offers, requests) = mpsc::sync_channel::<Vec<u8>>(0);
            let clipboard_type = mime_type.clone();
            thread::spawn(move || {
                for data in requests {
                    let transfer = (|| -> Result<()> {
                        let (mut stream, cipher) = loop {
                            let (mut stream, _) = listener.accept()?;
                            stream.set_read_timeout(Some(TIMEOUT))?;
                            stream.set_write_timeout(Some(TIMEOUT))?;
                            match handshake(&mut stream, &secret, true) {
                                Ok(cipher) => break (stream, cipher),
                                Err(error) => eprintln!("Rejected handshake: {error:#}"),
                            }
                        };
                        write_frame(&mut stream, &cipher, 2, mime_type.as_bytes())?;
                        write_frame(&mut stream, &cipher, 3, &data)?;
                        stream.set_read_timeout(None)?;
                        eprintln!("Waiting for client approval");
                        let accepted = read_frame(&mut stream, &cipher, 4, 2)
                            .context("client disconnected before accepting")?;
                        ensure!(accepted == b"OK", "invalid acceptance response");
                        eprintln!("Clipboard accepted");
                        Ok(())
                    })();
                    if let Err(error) = transfer {
                        eprintln!("transfer failed; run hemeo send to retry: {error:#}");
                    }
                }
            });
            eprintln!("Listening on {bind}; control socket: {}", socket.display());
            for connection in control.incoming() {
                let mut stream = match connection {
                    Ok(stream) => stream,
                    Err(error) => {
                        eprintln!("control connection: {error}");
                        continue;
                    }
                };
                let result = (|| -> Result<()> {
                    stream.set_read_timeout(Some(TIMEOUT))?;
                    stream.set_write_timeout(Some(TIMEOUT))?;
                    let mut command = [0; 5];
                    stream.read_exact(&mut command)?;
                    ensure!(&command == b"SEND\n", "unknown control command");
                    let output = Command::new("sh")
                        .args(["-c", &get_command])
                        .env("HEMEO_MIME_TYPE", &clipboard_type)
                        .stdin(Stdio::null())
                        .stderr(Stdio::inherit())
                        .output()
                        .context("run get command")?;
                    ensure!(
                        output.status.success(),
                        "get command failed: {}",
                        output.status
                    );
                    ensure!(
                        output.stdout.len() <= MAX_CLIPBOARD,
                        "clipboard exceeds 64 MiB"
                    );
                    offers
                        .try_send(output.stdout)
                        .map_err(|error| match error {
                            mpsc::TrySendError::Full(_) => {
                                anyhow::anyhow!("server busy with another clipboard offer")
                            }
                            mpsc::TrySendError::Disconnected(_) => {
                                anyhow::anyhow!("transfer worker stopped")
                            }
                        })?;
                    Ok(())
                })();
                let response = match result {
                    Ok(()) => "OK\n".to_owned(),
                    Err(error) => format!("ERR {error:#}\n"),
                };
                if let Err(error) = stream.write_all(response.as_bytes()) {
                    eprintln!("control response: {error}");
                }
            }
        }
        Action::Client {
            server,
            secret,
            socket,
            put_command,
            on_request,
            on_accept,
        } => {
            ensure!(
                !secret.is_empty() && secret.len() <= 4096,
                "secret must be 1..=4096 bytes"
            );
            let socket = socket_path(socket, false)?;
            let listener = control_listener(&socket)?;
            let pending: Arc<Mutex<Option<Pending>>> = Arc::new(Mutex::new(None));
            let incoming = Arc::clone(&pending);
            let (accepted, approvals) = mpsc::channel();
            thread::spawn(move || {
                loop {
                    let receive = || -> Result<Pending> {
                        let mut stream = TcpStream::connect(&server)?;
                        stream.set_read_timeout(Some(TIMEOUT))?;
                        stream.set_write_timeout(Some(TIMEOUT))?;
                        let cipher = handshake(&mut stream, &secret, false)?;
                        let mime_type =
                            String::from_utf8(read_frame(&mut stream, &cipher, 2, 256)?)?;
                        ensure!(
                            !mime_type.is_empty() && !mime_type.contains('\0'),
                            "invalid MIME type"
                        );
                        let data = read_frame(&mut stream, &cipher, 3, MAX_CLIPBOARD)?;
                        Ok(Pending {
                            stream,
                            cipher,
                            data,
                            mime_type,
                            server: server.clone(),
                        })
                    };
                    match receive() {
                        Ok(offer) => {
                            eprintln!(
                                "Clipboard offered by {} ({} bytes); run hemeo accept",
                                offer.server,
                                offer.data.len()
                            );
                            let mime_type = offer.mime_type.clone();
                            let bytes = offer.data.len();
                            *incoming.lock().unwrap() = Some(offer);
                            hook(&on_request, &server, &mime_type, bytes);
                            if approvals.recv().is_err() {
                                return;
                            }
                        }
                        Err(error) => eprintln!("receive: {error:#}"),
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            });
            eprintln!("Control socket: {}", socket.display());
            for connection in listener.incoming() {
                let mut stream = match connection {
                    Ok(stream) => stream,
                    Err(error) => {
                        eprintln!("control connection: {error}");
                        continue;
                    }
                };
                let result = (|| -> Result<()> {
                    stream.set_read_timeout(Some(TIMEOUT))?;
                    stream.set_write_timeout(Some(TIMEOUT))?;
                    let mut command = [0; 7];
                    stream.read_exact(&mut command)?;
                    ensure!(&command == b"ACCEPT\n", "unknown control command");
                    let mut pending = pending.lock().unwrap();
                    let offer = pending.as_mut().context("no pending clipboard offer")?;
                    let mut child = Command::new("sh")
                        .args(["-c", &put_command])
                        .env("HEMEO_SERVER", &offer.server)
                        .env("HEMEO_MIME_TYPE", &offer.mime_type)
                        .env("HEMEO_BYTES", offer.data.len().to_string())
                        .stdin(Stdio::piped())
                        .spawn()
                        .context("run put command")?;
                    let written = child.stdin.take().unwrap().write_all(&offer.data);
                    let status = child.wait()?;
                    written.context("write content to put command")?;
                    ensure!(status.success(), "put command failed: {status}");
                    let mut offer = pending.take().unwrap();
                    drop(pending);
                    if let Err(error) = write_frame(&mut offer.stream, &offer.cipher, 4, b"OK") {
                        eprintln!("clipboard copied, but acknowledgment failed: {error}");
                    }
                    hook(
                        &on_accept,
                        &offer.server,
                        &offer.mime_type,
                        offer.data.len(),
                    );
                    accepted.send(())?;
                    Ok(())
                })();
                let response = match result {
                    Ok(()) => "OK\n".to_owned(),
                    Err(error) => format!("ERR {error:#}\n"),
                };
                if let Err(error) = stream.write_all(response.as_bytes()) {
                    eprintln!("control response: {error}");
                }
            }
        }
        action @ (Action::Accept { .. } | Action::Send { .. }) => {
            let (socket, send) = match action {
                Action::Send { socket } => (socket, true),
                Action::Accept { socket } => (socket, false),
                _ => unreachable!(),
            };
            let socket = socket_path(socket, send)?;
            let mut stream = UnixStream::connect(&socket)
                .with_context(|| format!("connect to {}", socket.display()))?;
            stream.set_read_timeout(Some(TIMEOUT))?;
            stream.write_all(if send { b"SEND\n" } else { b"ACCEPT\n" })?;
            let mut response = String::new();
            stream.take(4096).read_to_string(&mut response)?;
            if response != "OK\n" {
                bail!("{}", response.trim_end());
            }
            println!(
                "{}",
                if send {
                    "Clipboard queued for sending"
                } else {
                    "Clipboard accepted"
                }
            );
        }
    }
    Ok(())
}
