//! The emails the account flows send (verification and password reset), and
//! the [`Mailer`] that sends them.

use crate::config::{MailSettings, SmtpSettings, SmtpTls};
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;

/// An SMTP server that does not answer within this is given up on.
const SMTP_TIMEOUT: Duration = Duration::from_secs(15);

/// The emails the service sends. Each has one call-to-action link.
pub enum Email<'a> {
    Verify { url: &'a str, valid_hours: i64 },
    Reset { url: &'a str, valid_minutes: i64 },
}

/// The words of one email; [`render_text`] and [`render_html`] lay them out.
struct Template<'a> {
    subject: &'static str,
    intro: String,
    url: &'a str,
    footer: &'static str,
}

fn plural(n: i64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

impl<'a> Email<'a> {
    fn template(&self) -> Template<'a> {
        match *self {
            Email::Verify { url, valid_hours } => Template {
                subject: "Verify your HE Engine account",
                intro: format!(
                    "Open the link below to activate your account and sign in. It expires in {}.",
                    plural(valid_hours, "hour")
                ),
                url,
                footer: "If you did not create this account, ignore this email.",
            },
            Email::Reset { url, valid_minutes } => Template {
                subject: "Reset your HE Engine password",
                intro: format!(
                    "Open the link below to choose a new password. It expires in {}.",
                    plural(valid_minutes, "minute")
                ),
                url,
                footer: "If you did not ask to reset your password, ignore this email.",
            },
        }
    }
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn render_text(t: &Template) -> String {
    format!(
        "{}\n\n{}\n\n{}\n\n{}\n",
        t.subject, t.intro, t.url, t.footer
    )
}

fn render_html(t: &Template) -> String {
    format!(
        "<!DOCTYPE html><html><body style=\"font-family:sans-serif;max-width:520px;margin:2rem auto\">\
         <h2>{subject}</h2><p>{intro}</p>\
         <p><a href=\"{url}\" style=\"color:#4f46e5\">{url}</a></p>\
         <p style=\"color:#555;font-size:0.85rem\">{footer}</p></body></html>",
        subject = escape_html(t.subject),
        intro = escape_html(&t.intro),
        url = escape_html(t.url),
        footer = escape_html(t.footer),
    )
}

/// Sends the service's emails. Built once at startup (inside the Tokio runtime:
/// the connection pool spawns a task), so SMTP settings are checked then and
/// connections are reused across requests.
pub struct Mailer {
    from: Mailbox,
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    log_links: bool,
}

fn transport(smtp: &SmtpSettings) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    type Transport = AsyncSmtpTransport<Tokio1Executor>;
    let invalid = |e: lettre::transport::smtp::Error| format!("SMTP_HOST {:?}: {e}", smtp.host);
    let builder = match smtp.tls {
        SmtpTls::StartTls => Transport::starttls_relay(&smtp.host).map_err(invalid)?,
        SmtpTls::Implicit => Transport::relay(&smtp.host).map_err(invalid)?,
        SmtpTls::None => {
            tracing::warn!(
                "SMTP_TLS=none: emails (which carry sign-in links) are sent unencrypted"
            );
            Transport::builder_dangerous(&smtp.host)
        }
    }
    .port(smtp.port)
    .timeout(Some(SMTP_TIMEOUT));
    Ok(match &smtp.credentials {
        Some((user, pass)) => builder
            .credentials(Credentials::new(user.clone(), pass.clone()))
            .build(),
        None => builder.build(),
    })
}

impl Mailer {
    pub fn new(settings: &MailSettings) -> Result<Self, String> {
        Ok(Mailer {
            from: settings.from.clone(),
            transport: settings.smtp.as_ref().map(transport).transpose()?,
            log_links: settings.log_links,
        })
    }

    /// Sends `email` to `to`. Failures are logged, never returned: the account
    /// flows answer the same way whether or not an email went out, so responses
    /// reveal nothing about which addresses have accounts.
    pub async fn send(&self, to: &str, email: Email<'_>) {
        let template = email.template();
        #[cfg(test)]
        outbox::record(to, template.url);
        let Some(transport) = &self.transport else {
            if self.log_links {
                tracing::info!(
                    "SMTP not configured; {:?} for {to}: {}",
                    template.subject,
                    template.url
                );
            } else {
                tracing::warn!(
                    "SMTP not configured; {:?} for {to} was not sent",
                    template.subject
                );
            }
            return;
        };
        if let Err(e) = self.deliver(transport, to, &template).await {
            tracing::error!("Failed to send {:?} to {to}: {e}", template.subject);
        }
    }

    async fn deliver(
        &self,
        transport: &AsyncSmtpTransport<Tokio1Executor>,
        to: &str,
        template: &Template<'_>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let message = Message::builder()
            .from(self.from.clone())
            .to(to.parse()?)
            .subject(template.subject)
            .multipart(MultiPart::alternative_plain_html(
                render_text(template),
                render_html(template),
            ))?;
        transport.send(message).await?;
        Ok(())
    }
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
    use crate::config::Config;

    const URL: &str = "https://app.example/heaas/verify#token=abc";

    #[test]
    fn templates_carry_the_link_and_its_lifetime() {
        let verify = Email::Verify {
            url: URL,
            valid_hours: 24,
        }
        .template();
        let html = render_html(&verify);
        assert_eq!(html.matches(URL).count(), 2);
        assert!(html.contains("<h2>Verify your HE Engine account</h2>"));
        assert!(html.contains("expires in 24 hours"));
        let text = render_text(&verify);
        assert!(text.contains(URL) && text.contains("expires in 24 hours"));

        let reset = Email::Reset {
            url: URL,
            valid_minutes: 1,
        }
        .template();
        assert!(reset.intro.ends_with("expires in 1 minute."));
    }

    #[test]
    fn html_is_escaped() {
        assert_eq!(
            escape_html(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    // The connection pool spawns its cleanup task, so this needs a runtime.
    #[actix_web::test]
    async fn transports_build_for_every_tls_mode() {
        let mut settings = Config::for_tests(std::env::temp_dir()).mail;
        for tls in [SmtpTls::StartTls, SmtpTls::Implicit, SmtpTls::None] {
            settings.smtp = Some(SmtpSettings {
                host: "smtp.example".into(),
                port: 2525,
                tls,
                credentials: Some(("user".into(), "pass".into())),
            });
            assert!(Mailer::new(&settings).unwrap().transport.is_some());
        }
    }
}
