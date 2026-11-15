use anyhow::{Context, Result, bail, ensure};
use std::{
    env, fs,
    io::ErrorKind,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
};

pub(crate) fn socket_path(socket: Option<PathBuf>, server: bool) -> Result<PathBuf> {
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

pub(crate) fn control_listener(socket: &std::path::Path) -> Result<UnixListener> {
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
