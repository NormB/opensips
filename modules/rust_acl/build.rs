//! build.rs — Extract `OPENSIPS_FULL_VERSION`, `OPENSIPS_COMPILE_FLAGS`,
//! and SCM info from the `OpenSIPS` source tree.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let src_dir = env::var("OPENSIPS_SRC_DIR")
        .unwrap_or_else(|_| "/usr/local/src/opensips".to_string());
    let src_path = Path::new(&src_dir);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    println!("cargo:rerun-if-env-changed=OPENSIPS_SRC_DIR");

    let dflags = opensips_build::extract_dflags(src_path);
    opensips_build::emit_scm_env(&dflags);

    // version_probe.c lives in the SDK directory
    let probe_src = manifest_dir.join("../rust/sdk/version_probe.c");

    if probe_src.exists() {
        let probe_bin = out_dir.join("version_probe");
        let mut cmd = Command::new("cc");
        cmd.arg("-o").arg(&probe_bin)
           .arg(&probe_src)
           .arg(format!("-I{src_dir}"));

        for (name, val) in &dflags {
            match val {
                Some(v) => { cmd.arg(format!("-D{name}={v}")); }
                None => { cmd.arg(format!("-D{name}")); }
            }
        }

        if let Ok(o) = cmd.output() {
            if o.status.success() {
                if let Ok(o) = Command::new(&probe_bin).output() {
                    if o.status.success() {
                        let stdout = String::from_utf8_lossy(&o.stdout);
                        for line in stdout.lines() {
                            if let Some(v) = line.strip_prefix("FULL_VERSION=") {
                                println!("cargo:rustc-env=OPENSIPS_FULL_VERSION={v}");
                            } else if let Some(v) = line.strip_prefix("COMPILE_FLAGS=") {
                                println!("cargo:rustc-env=OPENSIPS_COMPILE_FLAGS={v}");
                            }
                        }
                        return;
                    }
                }
            } else {
                eprintln!("cargo:warning=version probe failed: {}",
                    String::from_utf8_lossy(&o.stderr));
            }
        }
    }

    println!("cargo:rustc-env=OPENSIPS_FULL_VERSION=unknown");
    println!("cargo:rustc-env=OPENSIPS_COMPILE_FLAGS=unknown");
}
