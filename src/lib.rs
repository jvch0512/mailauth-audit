//! Offline analysis of email authentication DNS records (SPF, DKIM, DMARC).
pub mod dkim;
pub mod dmarc;
pub mod spf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
    pub fn parse(s: &str) -> Option<Severity> {
        Some(match s {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
}

pub(crate) fn finding(
    severity: Severity,
    code: &'static str,
    message: impl Into<String>,
) -> Finding {
    Finding {
        severity,
        code,
        message: message.into(),
    }
}

/// Parse `tag=value; tag=value` records (DMARC and DKIM). Tag names are lower-cased; the first occurrence wins.
pub(crate) fn parse_tags(record: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for part in record.split(';') {
        if let Some((k, v)) = part.split_once('=') {
            let k = k.trim().to_ascii_lowercase();
            if !k.is_empty() && !out.iter().any(|(e, _)| *e == k) {
                out.push((k, v.trim().to_string()));
            }
        }
    }
    out
}

pub(crate) fn tag<'a>(tags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}
