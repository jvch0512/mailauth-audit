use crate::{finding, parse_tags, tag, Finding, Severity};

/// Audit the DMARC TXT record published at `_dmarc.<domain>`.
pub fn audit(records: &[&str]) -> Vec<Finding> {
    let found: Vec<&&str> = records
        .iter()
        .filter(|r| r.trim_start().to_ascii_lowercase().starts_with("v=dmarc1"))
        .collect();
    match found.len() {
        0 => {
            return vec![finding(
                Severity::High,
                "DMARC_MISSING",
                "no DMARC record: receivers cannot be told to reject spoofed mail",
            )]
        }
        1 => {}
        _ => {
            return vec![finding(
                Severity::High,
                "DMARC_MULTIPLE",
                "multiple DMARC records; receivers ignore all of them (RFC 7489 6.6.3)",
            )]
        }
    }
    let tags = parse_tags(found[0]);
    let mut out = Vec::new();
    match tag(&tags, "p").map(str::to_ascii_lowercase).as_deref() {
        Some("reject") => {}
        Some("quarantine") => out.push(finding(
            Severity::Low,
            "DMARC_QUARANTINE",
            "p=quarantine is good; p=reject gives full protection once reports look clean",
        )),
        Some("none") => out.push(finding(
            Severity::Medium,
            "DMARC_MONITOR_ONLY",
            "p=none only monitors; spoofed mail is still delivered",
        )),
        Some(other) => out.push(finding(
            Severity::High,
            "DMARC_BAD_POLICY",
            format!("invalid p= value '{other}'"),
        )),
        None => out.push(finding(
            Severity::High,
            "DMARC_NO_POLICY",
            "required p= tag is missing, so the record is invalid",
        )),
    }
    if let Some(sp) = tag(&tags, "sp").map(str::to_ascii_lowercase) {
        if sp == "none" && tag(&tags, "p").map(|p| p.eq_ignore_ascii_case("none")) != Some(true) {
            out.push(finding(
                Severity::Medium,
                "DMARC_WEAK_SUBDOMAIN",
                "sp=none leaves subdomains spoofable even though the main domain is enforced",
            ));
        }
    }
    if let Some(pct) = tag(&tags, "pct") {
        match pct.parse::<u32>() {
            Ok(100) => {}
            Ok(n) if n <= 100 => out.push(finding(
                Severity::Medium,
                "DMARC_PARTIAL",
                format!("pct={n}: the policy applies to only {n}% of failing mail"),
            )),
            _ => out.push(finding(
                Severity::Low,
                "DMARC_BAD_PCT",
                format!("invalid pct value '{pct}'"),
            )),
        }
    }
    match tag(&tags, "rua") {
        None => out.push(finding(Severity::Medium, "DMARC_NO_REPORTS", "no rua= address: you will not receive aggregate reports to find legitimate senders that fail")),
        Some(v) if !v.to_ascii_lowercase().contains("mailto:") => out.push(finding(Severity::Low, "DMARC_BAD_RUA", "rua= must be a mailto: URI")),
        _ => {}
    }
    for (name, code, what) in [
        ("adkim", "DMARC_RELAXED_DKIM", "DKIM"),
        ("aspf", "DMARC_RELAXED_SPF", "SPF"),
    ] {
        if tag(&tags, name).map(|v| v.eq_ignore_ascii_case("s")) != Some(true) {
            out.push(finding(Severity::Info, code, format!("{what} alignment is relaxed (default): subdomains may pass for the organizational domain; strict alignment ({name}=s) is tighter")));
        }
    }
    out
}
