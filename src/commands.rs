use anyhow::{Context, Result, bail, ensure};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    process::{Command, Stdio},
};

use crate::{MAX_CLIPBOARD, TIMEOUT, cli::Action, control::socket_path};

pub(crate) fn run(action: Action) -> Result<()> {
    let (socket, content, put_command) = match action {
        Action::Send {
            socket,
            mime_type,
            get_command,
        } => {
            ensure!(
                !mime_type.is_empty() && mime_type.len() <= 256 && !mime_type.contains('\0'),
                "MIME type must be 1..=256 bytes without NUL"
            );
            let output = Command::new("sh")
                .args(["-c", &get_command])
                .env("HEMEO_MIME_TYPE", &mime_type)
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
            (socket, Some((mime_type, output.stdout)), None)
        }
        Action::Accept {
            socket,
            put_command,
        } => (socket, None, Some(put_command)),
        _ => unreachable!(),
    };
    let send = content.is_some();
    let socket = socket_path(socket, send)?;
    let mut stream =
        UnixStream::connect(&socket).with_context(|| format!("connect to {}", socket.display()))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.write_all(if send { b"SEND\n" } else { b"ACCEPT\n" })?;
    if let Some((mime_type, data)) = content {
        stream.write_all(&u32::try_from(mime_type.len())?.to_be_bytes())?;
        stream.write_all(mime_type.as_bytes())?;
        stream.write_all(&u32::try_from(data.len())?.to_be_bytes())?;
        stream.write_all(&data)?;
    }
    if let Some(put_command) = put_command {
        let mut response = [0; 5];
        stream.read_exact(&mut response)?;
        if &response != b"DATA\n" {
            let mut error = String::from_utf8_lossy(&response).into_owned();
            Read::by_ref(&mut stream)
                .take(4096)
                .read_to_string(&mut error)?;
            bail!("{}", error.trim_end());
        }
        let mut fields = Vec::new();
        for limit in [4096, 256, MAX_CLIPBOARD] {
            let mut length = [0; 4];
            stream.read_exact(&mut length)?;
            let length = u32::from_be_bytes(length) as usize;
            ensure!(length <= limit, "invalid offer field length");
            let mut data = vec![0; length];
            stream.read_exact(&mut data)?;
            fields.push(data);
        }
        let mut fields = fields.into_iter();
        let server = String::from_utf8(fields.next().unwrap())?;
        let mime_type = String::from_utf8(fields.next().unwrap())?;
        ensure!(
            !server.contains('\0') && !mime_type.is_empty() && !mime_type.contains('\0'),
            "invalid offer metadata"
        );
        let data = fields.next().unwrap();
        let mut child = Command::new("sh")
            .args(["-c", &put_command])
            .env("HEMEO_SERVER", &server)
            .env("HEMEO_MIME_TYPE", &mime_type)
            .env("HEMEO_BYTES", data.len().to_string())
            .stdin(Stdio::piped())
            .spawn()
            .context("run put command")?;
        let written = child.stdin.take().unwrap().write_all(&data);
        let status = child.wait()?;
        written.context("write content to put command")?;
        ensure!(status.success(), "put command failed: {status}");
        stream.write_all(b"OK\n")?;
    }
    let mut response = String::new();
    stream.take(4096).read_to_string(&mut response)?;
    if response != "OK\n" {
        bail!("{}", response.trim_end());
    }
    if send {
        println!("Clipboard queued for sending");
    } else {
        eprintln!("Clipboard accepted");
    }
    Ok(())
}
