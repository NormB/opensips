//! opensips-build — Shared build-time helpers for OpenSIPS Rust modules.
//!
//! Extracts -D flags, SCM version info, and full version strings from
//! the OpenSIPS source tree. Used as a `[build-dependencies]` by all
//! module and service build.rs files to eliminate duplicated logic.

use std::path::Path;
use std::process::Command;

/// A parsed -D flag: name and optional value.
pub type DFlag = (String, Option<String>);

/// Extract all -D flags from OpenSIPS's `make -n -B` dry-run output.
///
/// This is the canonical way to discover what defines OpenSIPS was
/// built with, ensuring Rust modules match the exact configuration.
pub fn extract_dflags(src: &Path) -> Vec<DFlag> {
    let output = Command::new("make")
        .arg("-n")
        .arg("-B")
        .current_dir(src)
        .output();

    let stdout = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(e) => {
            eprintln!("cargo:warning=Failed to run make -n -B: {}", e);
            return Vec::new();
        }
    };

    let cc_line = stdout
        .lines()
        .find(|l| l.starts_with("cc ") || l.starts_with("gcc "));

    match cc_line {
        Some(line) => parse_dflags(line),
        None => {
            eprintln!("cargo:warning=No cc line found in make -n -B output");
            Vec::new()
        }
    }
}

/// Parse -D flags from a compiler command line.
///
/// Handles: `-DFOO`, `-DFOO=BAR`, `-DFOO='"string"'`, `-DFOO='"/path/"'`
pub fn parse_dflags(line: &str) -> Vec<DFlag> {
    let mut flags = Vec::new();
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if i + 1 < chars.len() && chars[i] == '-' && chars[i + 1] == 'D' {
            i += 2;
            let start = i;
            let mut in_sq = false;
            let mut in_dq = false;
            while i < chars.len() {
                match chars[i] {
                    '\'' if !in_dq => in_sq = !in_sq,
                    '"' if !in_sq => in_dq = !in_dq,
                    ' ' | '\t' if !in_sq && !in_dq => break,
                    _ => {}
                }
                i += 1;
            }
            let token: String = chars[start..i].iter().collect();
            if let Some(eq) = token.find('=') {
                let name = token[..eq].to_string();
                let mut val = token[eq + 1..].to_string();
                if val.starts_with('\'') && val.ends_with('\'') {
                    val = val[1..val.len() - 1].to_string();
                }
                flags.push((name, Some(val)));
            } else {
                flags.push((token, None));
            }
        } else {
            i += 1;
        }
    }
    flags
}

/// SCM version info extracted from OpenSIPS -D flags.
pub struct ScmInfo {
    pub scm_type: String,
    pub scm_rev: String,
}

/// Extract VERSIONTYPE and THISREVISION from parsed -D flags.
///
/// These correspond to `OPENSIPS_SCM_TYPE` and `OPENSIPS_SCM_REV`
/// in the module's `scm_version` struct, which OpenSIPS 4.0
/// validates at module load time.
pub fn extract_scm_info(dflags: &[DFlag]) -> ScmInfo {
    let mut scm_type = "unknown".to_string();
    let mut scm_rev = "unknown".to_string();

    for (name, val) in dflags {
        if name == "VERSIONTYPE" {
            if let Some(v) = val {
                scm_type = v.trim_matches('"').to_string();
            }
        } else if name == "THISREVISION" {
            if let Some(v) = val {
                scm_rev = v.trim_matches('"').to_string();
            }
        }
    }

    ScmInfo { scm_type, scm_rev }
}

/// Emit cargo:rustc-env directives for SCM info.
///
/// Call this from build.rs after extracting dflags:
/// ```no_run
/// let src_path = std::path::Path::new("/usr/local/src/opensips");
/// let dflags = opensips_build::extract_dflags(src_path);
/// opensips_build::emit_scm_env(&dflags);
/// ```
pub fn emit_scm_env(dflags: &[DFlag]) {
    let scm = extract_scm_info(dflags);
    println!("cargo:rustc-env=OPENSIPS_SCM_TYPE={}", scm.scm_type);
    println!("cargo:rustc-env=OPENSIPS_SCM_REV={}", scm.scm_rev);
}
