use crate::{finding, Finding, Severity};

/// Maximum DNS-querying terms allowed by RFC 7208 section 4.6.4.
pub const LOOKUP_LIMIT: usize = 10;

/// Audit the SPF TXT records published at a domain (pass every TXT string that starts with `v=spf1`).
pub fn audit(records: &[&str]) -> Vec<Finding> {
    let spf: Vec<&&str> = records
        .iter()
        .filter(|r| r.trim_start().to_ascii_lowercase().starts_with("v=spf1"))
        .collect();
    match spf.len() {
        0 => {
            return vec![finding(
                Severity::High,
                "SPF_MISSING",
                "no SPF record: anyone can claim to send as this domain",
            )]
        }
        1 => {}
        n => {
            return vec![finding(
                Severity::High,
                "SPF_MULTIPLE",
                format!("{n} SPF records published; receivers return permerror (RFC 7208 4.5)"),
            )]
        }
    }
    let record = spf[0].trim();
    let mut out = Vec::new();
    let terms: Vec<&str> = record.split_whitespace().skip(1).collect();
    let mut lookups = 0usize;
    let mut all: Option<&str> = None;
    let mut redirect = false;
    for t in &terms {
        let lower = t.to_ascii_lowercase();
        let body = lower.trim_start_matches(['+', '-', '~', '?']);
        if body == "all" {
            all = Some(match lower.chars().next() {
                Some('-') => "-",
                Some('~') => "~",
                Some('?') => "?",
                _ => "+",
            });
        } else if body.starts_with("include:")
            || body.starts_with("exists:")
            || body == "a"
            || body.starts_with("a:")
            || body.starts_with("a/")
            || body == "mx"
            || body.starts_with("mx:")
            || body.starts_with("mx/")
        {
            lookups += 1;
        } else if body.starts_with("ptr") {
            lookups += 1;
            out.push(finding(
                Severity::Medium,
                "SPF_PTR",
                "the ptr mechanism is deprecated, slow and unreliable (RFC 7208 5.5)",
            ));
        } else if body.starts_with("redirect=") {
            lookups += 1;
            redirect = true;
        }
    }
    match all {
        Some("+") => out.push(finding(Severity::Critical, "SPF_PASS_ALL", "'+all' authorises every sender on the internet")),
        Some("?") => out.push(finding(Severity::High, "SPF_NEUTRAL_ALL", "'?all' gives no protection against spoofing")),
        Some("~") => out.push(finding(Severity::Low, "SPF_SOFTFAIL", "'~all' is acceptable while rolling out, move to '-all' (with DMARC enforcement) when stable")),
        Some("-") => {}
        _ if redirect => {}
        _ => out.push(finding(Severity::High, "SPF_NO_ALL", "record has no terminating 'all' or redirect; unlisted senders get a neutral result")),
    }
    if lookups > LOOKUP_LIMIT {
        out.push(finding(Severity::High, "SPF_TOO_MANY_LOOKUPS", format!("{lookups} DNS-querying terms exceed the limit of {LOOKUP_LIMIT}: evaluation fails with permerror (nested includes add more)")));
    } else if lookups >= 8 {
        out.push(finding(
            Severity::Low,
            "SPF_NEAR_LOOKUP_LIMIT",
            format!("{lookups} of {LOOKUP_LIMIT} lookups used before counting nested includes"),
        ));
    }
    if record.len() > 450 {
        out.push(finding(
            Severity::Low,
            "SPF_LONG",
            "record is long; UDP DNS answers above 512 bytes may fail without TCP fallback",
        ));
    }
    out
}
