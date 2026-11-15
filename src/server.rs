use anyhow::{Context, Result, ensure};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::mpsc,
    thread,
};

use crate::{
    MAX_CLIPBOARD, TIMEOUT,
    control::{control_listener, socket_path},
    protocol::{handshake, read_frame, write_frame},
};

pub(crate) fn run(bind: String, secret: String, socket: Option<PathBuf>) -> Result<()> {
    ensure!(
        !secret.is_empty() && secret.len() <= 4096,
        "secret must be 1..=4096 bytes"
    );
    let listener = TcpListener::bind(&bind).context("bind TCP listener")?;
    let socket = socket_path(socket, true)?;
    let control = control_listener(&socket)?;
    let (offers, requests) = mpsc::sync_channel::<(String, Vec<u8>)>(0);
    thread::spawn(move || {
        for (mime_type, data) in requests {
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
            let mut length = [0; 4];
            stream.read_exact(&mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            ensure!((1..=256).contains(&length), "invalid MIME type length");
            let mut mime_type = vec![0; length];
            stream.read_exact(&mut mime_type)?;
            let mime_type = String::from_utf8(mime_type)?;
            ensure!(!mime_type.contains('\0'), "invalid MIME type");
            let mut length = [0; 4];
            stream.read_exact(&mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            ensure!(length <= MAX_CLIPBOARD, "clipboard exceeds 64 MiB");
            let mut data = vec![0; length];
            stream.read_exact(&mut data)?;
            offers
                .try_send((mime_type, data))
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
    Ok(())
}
