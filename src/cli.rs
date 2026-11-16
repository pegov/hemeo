use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "hemeo",
    version,
    about = "Send clipboard content with explicit approval"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Action,
}

#[derive(Subcommand)]
pub(crate) enum Action {
    #[command(about = "Run the clipboard server; trigger transfers with hemeo send")]
    Server {
        #[arg(long, default_value = "127.0.0.1:7331")]
        bind: String,
        #[arg(long, env = "HEMEO_SECRET")]
        secret: String,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    #[command(about = "Wait for offers; reconnect automatically")]
    Client {
        #[arg(long)]
        server: String,
        #[arg(long, env = "HEMEO_SECRET")]
        secret: String,
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(long, help = "Shell command to run when an offer arrives")]
        on_request: Option<String>,
        #[arg(long, help = "Shell command to run after copying succeeds")]
        on_accept: Option<String>,
        #[arg(long, help = "Show a system tray icon with an Accept action")]
        tray: bool,
    },
    #[command(about = "Offer the current clipboard through the running server")]
    Send {
        #[arg(long, default_value = "text/plain")]
        mime_type: String,
        #[arg(
            long,
            default_value = "wl-paste --no-newline --type \"$HEMEO_MIME_TYPE\"",
            help = "Shell command whose stdout supplies the content to send"
        )]
        get_command: String,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    #[command(about = "Copy the pending offer to the local clipboard")]
    Accept {
        #[arg(
            long,
            default_value = "wl-copy --type \"$HEMEO_MIME_TYPE\"",
            help = "Shell command receiving the content on stdin after acceptance"
        )]
        put_command: String,
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}
