use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Result, ensure};
use argon2::Argon2;
use std::{
    io::{Read, Write},
    net::TcpStream,
};

use crate::TIMEOUT;

const PROTOCOL: &[u8; 7] = b"hemeo\0\x01";

pub(crate) fn read_frame(
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

pub(crate) fn write_frame(
    stream: &mut TcpStream,
    cipher: &Aes256Gcm,
    message: u8,
    data: &[u8],
) -> Result<()> {
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

pub(crate) fn handshake(stream: &mut TcpStream, secret: &str, server: bool) -> Result<Aes256Gcm> {
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
