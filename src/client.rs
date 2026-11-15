use aes_gcm::Aes256Gcm;
use anyhow::{Context, Result, ensure};
use std::{
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use crate::{
    MAX_CLIPBOARD, TIMEOUT,
    control::{control_listener, socket_path},
    protocol::{handshake, read_frame, write_frame},
};

struct Pending {
    stream: TcpStream,
    cipher: Aes256Gcm,
    data: Vec<u8>,
    mime_type: String,
    server: String,
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

pub(crate) fn run(
    server: String,
    secret: String,
    socket: Option<PathBuf>,
    on_request: Option<String>,
    on_accept: Option<String>,
) -> Result<()> {
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
                let mime_type = String::from_utf8(read_frame(&mut stream, &cipher, 2, 256)?)?;
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
            ensure!(
                offer.server.len() <= 4096,
                "server address exceeds 4096 bytes"
            );
            stream.write_all(b"DATA\n")?;
            for data in [
                offer.server.as_bytes(),
                offer.mime_type.as_bytes(),
                &offer.data,
            ] {
                stream.write_all(&u32::try_from(data.len())?.to_be_bytes())?;
                stream.write_all(data)?;
            }
            stream.set_read_timeout(None)?;
            let mut response = [0; 3];
            stream.read_exact(&mut response)?;
            ensure!(&response == b"OK\n", "content was not accepted");
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
    Ok(())
}
