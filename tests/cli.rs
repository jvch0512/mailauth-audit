use std::process::Command;

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_mailauth-audit"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn sample_file_fails_and_lists_worst_first() {
    let sample = concat!(env!("CARGO_MANIFEST_DIR"), "/samples/example.records");
    let (code, out) = run(&[sample]);
    assert_eq!(code, 1);
    let first = out.lines().next().unwrap();
    assert!(
        first.contains("HIGH") || first.contains("CRITICAL"),
        "worst finding first: {first}"
    );
    assert!(
        out.contains("SPF_TOO_MANY_LOOKUPS")
            && out.contains("DMARC_MONITOR_ONLY")
            && out.contains("DKIM_TEST_MODE")
    );
}

#[test]
fn clean_records_exit_zero_and_fail_on_threshold() {
    let dir = std::env::temp_dir().join(format!("mailauth_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key = "A".repeat(392);
    let f = dir.join("good.records");
    std::fs::write(&f, format!("# good\nspf: \"v=spf1 include:_spf.example.com -all\"\ndmarc: v=DMARC1; p=reject; rua=mailto:d@example.com; adkim=s; aspf=s\ndkim s1: v=DKIM1; k=rsa; p={key}\n")).unwrap();
    assert_eq!(run(&[f.to_str().unwrap()]).0, 0);
    let weak = dir.join("weak.records");
    std::fs::write(&weak, "spf: v=spf1 mx ~all\ndmarc: v=DMARC1; p=reject; rua=mailto:d@example.com; adkim=s; aspf=s\ndkim s1: v=DKIM1; p=\n").unwrap();
    assert_eq!(
        run(&[weak.to_str().unwrap()]).0,
        1,
        "low finding fails the default threshold"
    );
    assert_eq!(
        run(&["--fail-on", "high", weak.to_str().unwrap()]).0,
        0,
        "but not a high threshold"
    );
}

#[test]
fn json_output_and_errors() {
    let dir = std::env::temp_dir().join(format!("mailauth_j_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("x.records");
    std::fs::write(&f, "spf: v=spf1 +all\n").unwrap();
    let (_, out) = run(&["--json", f.to_str().unwrap()]);
    assert!(out.trim_start().starts_with('[') && out.contains("\"code\":\"SPF_PASS_ALL\""));
    assert_eq!(run(&[]).0, 2);
    assert_eq!(run(&["/no/such/file"]).0, 2);
    std::fs::write(&f, "bogus line\n").unwrap();
    assert_eq!(run(&[f.to_str().unwrap()]).0, 2);
    std::fs::write(&f, "txt: hello\n").unwrap();
    assert_eq!(run(&[f.to_str().unwrap()]).0, 2);
}
