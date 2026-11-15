use std::{path::PathBuf, thread};

use crate::{cli::Action, commands};

pub(crate) struct Tray {
    pub(crate) pending: bool,
    pub(crate) socket: PathBuf,
}

impl ksni::Tray for Tray {
    fn id(&self) -> String {
        "hemeo".into()
    }

    fn title(&self) -> String {
        if self.pending {
            "hemeo — clipboard offer pending"
        } else {
            "hemeo — waiting for offers"
        }
        .into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let color = if self.pending {
            [255, 255, 180, 0]
        } else {
            [255, 120, 120, 120]
        };
        vec![ksni::Icon {
            width: 16,
            height: 16,
            data: color.repeat(16 * 16),
        }]
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            ksni::menu::StandardItem {
                label: "Accept clipboard".into(),
                enabled: self.pending,
                activate: Box::new(|tray: &mut Self| {
                    let socket = tray.socket.clone();
                    thread::spawn(move || {
                        if let Err(error) = commands::run(Action::Accept {
                            socket: Some(socket),
                            put_command: "wl-copy --type \"$HEMEO_MIME_TYPE\"".into(),
                        }) {
                            eprintln!("tray accept: {error:#}");
                        }
                    });
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}
