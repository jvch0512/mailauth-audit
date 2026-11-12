use mailauth_audit::{dkim, dmarc, spf, Finding, Severity};
use std::process::ExitCode;

const USAGE: &str = "usage: mailauth-audit [--fail-on SEVERITY] [--json] <records-file>\n\nFile format, one record per line (blank lines and # comments ignored):\n  spf:   v=spf1 include:_spf.example.com -all\n  dmarc: v=DMARC1; p=reject; rua=mailto:dmarc@example.com\n  dkim <selector>: v=DKIM1; k=rsa; p=MIGf...\n\nFetch records with: dig +short TXT example.com / _dmarc.example.com / sel._domainkey.example.com";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (mut fail_on, mut json, mut path) = (Severity::Low, false, None);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--json" => json = true,
            "--fail-on" => match args.next().as_deref().and_then(Severity::parse) {
                Some(s) => fail_on = s,
                None => return usage(),
            },
            "-h" | "--help" => return usage(),
            _ if path.is_none() && !a.starts_with('-') => path = Some(a),
            _ => return usage(),
        }
    }
    let Some(path) = path else { return usage() };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let (mut spf_records, mut dmarc_records) = (Vec::new(), Vec::new());
    let mut dkim_records: Vec<(String, String)> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((label, value)) = line.split_once(':') else {
            eprintln!("error: line {}: expected '<type>: <record>'", n + 1);
            return ExitCode::from(2);
        };
        let value = value.trim().trim_matches('"').to_string();
        let label = label.trim();
        if label.eq_ignore_ascii_case("spf") {
            spf_records.push(value);
        } else if label.eq_ignore_ascii_case("dmarc") {
            dmarc_records.push(value);
        } else if let Some(sel) = label.strip_prefix("dkim ") {
            dkim_records.push((sel.trim().to_string(), value));
        } else {
            eprintln!("error: line {}: unknown record type '{label}'", n + 1);
            return ExitCode::from(2);
        }
    }
    let mut report: Vec<(&str, Finding)> = Vec::new();
    let spf_refs: Vec<&str> = spf_records.iter().map(String::as_str).collect();
    let dmarc_refs: Vec<&str> = dmarc_records.iter().map(String::as_str).collect();
    report.extend(spf::audit(&spf_refs).into_iter().map(|f| ("SPF", f)));
    report.extend(dmarc::audit(&dmarc_refs).into_iter().map(|f| ("DMARC", f)));
    if dkim_records.is_empty() {
        report.push(("DKIM", Finding { severity: Severity::Medium, code: "DKIM_NONE_PROVIDED", message: "no DKIM selector supplied; add 'dkim <selector>: <record>' lines to audit signing keys".into() }));
    }
    for (sel, rec) in &dkim_records {
        report.extend(dkim::audit(sel, rec).into_iter().map(|f| ("DKIM", f)));
    }
    report.sort_by_key(|b| std::cmp::Reverse(b.1.severity.rank()));
    if json {
        let items: Vec<String> = report.iter().map(|(area, f)| format!("  {{\"area\":\"{area}\",\"severity\":\"{}\",\"code\":\"{}\",\"message\":\"{}\"}}", f.severity.as_str(), f.code, f.message.replace('\\', "\\\\").replace('"', "\\\""))).collect();
        println!("[\n{}\n]", items.join(",\n"));
    } else {
        for (area, f) in &report {
            println!(
                "[{:8}] {:5} {}: {}",
                f.severity.as_str().to_uppercase(),
                area,
                f.code,
                f.message
            );
        }
        println!("{} finding(s)", report.len());
    }
    if report
        .iter()
        .any(|(_, f)| f.severity.rank() >= fail_on.rank() && f.severity != Severity::Info)
    {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}
