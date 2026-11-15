mod cli;
mod client;
mod commands;
mod control;
mod protocol;
mod server;

use anyhow::Result;
use clap::Parser;
use std::time::Duration;

use cli::{Action, Cli};

const MAX_CLIPBOARD: usize = 64 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

fn main() -> Result<()> {
    match Cli::parse().command {
        Action::Server {
            bind,
            secret,
            socket,
        } => server::run(bind, secret, socket),
        Action::Client {
            server,
            secret,
            socket,
            on_request,
            on_accept,
        } => client::run(server, secret, socket, on_request, on_accept),
        action @ (Action::Accept { .. } | Action::Send { .. }) => commands::run(action),
    }
}
