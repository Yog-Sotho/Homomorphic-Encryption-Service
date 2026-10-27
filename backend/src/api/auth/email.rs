//! The emails the account flows send (verification and password reset).

use crate::config::Config;
use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// An email with one call-to-action link.
pub struct LinkEmail<'a> {
    pub subject: &'a str,
    pub intro: &'a str,
    pub url: &'a str,
    pub footer: &'a str,
}

fn render(email: &LinkEmail) -> String {
    format!(
        "<!DOCTYPE html><html><body style=\"font-family:sans-serif;max-width:520px;margin:2rem auto\">\
         <h2>{subject}</h2><p>{intro}</p>\
         <p><a href=\"{url}\" style=\"color:#6366f1\">{url}</a></p>\
         <p style=\"color:#888;font-size:0.85rem\">{footer}</p></body></html>",
        subject = email.subject,
        intro = email.intro,
        url = email.url,
        footer = email.footer,
    )
}

/// Sends `email` to `to`. Failures are logged, never returned: the account
/// flows answer the same way whether or not an email went out, so responses
/// reveal nothing about which addresses have accounts.
pub async fn send(config: &Config, to: &str, email: LinkEmail<'_>) {
    #[cfg(test)]
    outbox::record(to, email.url);
    let Some(smtp_host) = config.smtp_host.as_deref() else {
        if config.log_email_links {
            log::info!(
                "SMTP not configured; {:?} for {to}: {}",
                email.subject,
                email.url
            );
        } else {
            log::warn!(
                "SMTP not configured; {:?} for {to} was not sent",
                email.subject
            );
        }
        return;
    };
    if let Err(e) = deliver(config, smtp_host, to, &email).await {
        log::error!("Failed to send {:?} to {to}: {e}", email.subject);
    }
}

async fn deliver(
    config: &Config,
    smtp_host: &str,
    to: &str,
    email: &LinkEmail<'_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let from: Mailbox = config.from_email.parse()?;
    let message = Message::builder()
        .from(from)
        .to(to.parse()?)
        .subject(email.subject)
        .header(ContentType::TEXT_HTML)
        .body(render(email))?;
    let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(smtp_host)?.port(config.smtp_port);
    let mailer = match (config.smtp_user.as_deref(), config.smtp_pass.as_deref()) {
        (Some(user), Some(pass)) => transport
            .credentials(Credentials::new(user.to_string(), pass.to_string()))
            .build(),
        _ => transport.build(),
    };
    mailer.send(message).await?;
    Ok(())
}

/// Every email "sent" by tests, so they can follow the links.
#[cfg(test)]
pub mod outbox {
    use std::sync::Mutex;

    static SENT: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

    pub(super) fn record(to: &str, url: &str) {
        SENT.lock().unwrap().push((to.to_string(), url.to_string()));
    }

    /// Links sent to `to`, oldest first.
    pub fn links_to(to: &str) -> Vec<String> {
        SENT.lock()
            .unwrap()
            .iter()
            .filter(|(addr, _)| addr == to)
            .map(|(_, url)| url.clone())
            .collect()
    }

    /// The token in the latest link sent to `to`.
    pub fn latest_token(to: &str) -> String {
        let link = links_to(to).pop().expect("an email was sent");
        link.split_once("#token=")
            .expect("link has a token")
            .1
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_link_once_per_place() {
        let html = render(&LinkEmail {
            subject: "Verify",
            intro: "Click",
            url: "https://app.example/heaas/verify#token=abc",
            footer: "Ignore",
        });
        assert_eq!(
            html.matches("https://app.example/heaas/verify#token=abc")
                .count(),
            2
        );
        assert!(html.contains("<h2>Verify</h2>"));
    }
}
