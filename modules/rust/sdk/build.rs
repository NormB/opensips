//! build.rs — Auto-detect `OpenSIPS` version and compile flags, generate bindings.
//!
//! Instead of hardcoding defines, we extract them from `OpenSIPS`'s own
//! build system via `make -n -B` dry-run. This ensures our bindings
//! match the exact configuration the server was built with.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[allow(clippy::too_many_lines)]
fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Locate `OpenSIPS` source
    let src_dir = env::var("OPENSIPS_SRC_DIR")
        .unwrap_or_else(|_| "/usr/local/src/opensips".to_string());
    let src_path = Path::new(&src_dir);

    assert!(
        src_path.join("Makefile.defs").exists(),
        "`OpenSIPS` source not found at {src_dir}. Set OPENSIPS_SRC_DIR.",
    );

    println!("cargo:rerun-if-env-changed=OPENSIPS_SRC_DIR");
    println!("cargo:rerun-if-changed=bindings.h.in");
    println!("cargo:rerun-if-changed=shim.c");

    // Parse version from Makefile.defs
    let (ver_major, ver_minor) = parse_version(src_path);
    println!("cargo:rustc-env=OPENSIPS_VERSION_MAJOR={ver_major}");
    println!("cargo:rustc-env=OPENSIPS_VERSION_MINOR={ver_minor}");

    // Extract -D flags from `OpenSIPS` build system
    let dflags = extract_opensips_dflags(src_path);

    // Build #define directives for the header
    let defines_for_header: String = dflags
        .iter()
        .map(|(name, val)| val.as_ref().map_or_else(
            || format!("#define {name}"),
            |v| format!("#define {name} {v}"),
        ))
        .collect::<Vec<_>>()
        .join("\n");

    // Run version probe to extract exact OPENSIPS_FULL_VERSION and OPENSIPS_COMPILE_FLAGS
    let (full_version, compile_flags) = probe_version_strings(src_path, &dflags);
    println!("cargo:rustc-env=OPENSIPS_FULL_VERSION={full_version}");
    println!("cargo:rustc-env=OPENSIPS_COMPILE_FLAGS={compile_flags}");

    // Generate bindings.h from template
    let template = fs::read_to_string("bindings.h.in").expect("Failed to read bindings.h.in");
    let generated = template
        .replace("@@OPENSIPS_SRC_DIR@@", &src_dir)
        .replace("@@VERSION_DEFS@@", "") // Version comes from the extracted flags
        .replace("@@MAKEFILE_DEFS@@", "") // DEFS come from extracted flags
        .replace("@@ARCH_DEFS@@", &defines_for_header);

    let bindings_h = out_dir.join("bindings.h");
    fs::write(&bindings_h, &generated).expect("Failed to write bindings.h");

    // Run bindgen
    let bindings = bindgen::Builder::default()
        .header(bindings_h.to_str().unwrap())
        .clang_arg(format!("-I{src_dir}"))
        // Allow the types we need
        .allowlist_type("module_exports")
        .allowlist_type("cmd_export_.*")
        .allowlist_type("cmd_param")
        .allowlist_type("param_export_.*")
        .allowlist_type("mi_export_.*")
        .allowlist_type("mi_recipe_.*")
        // Statistics framework
        .allowlist_type("stat_export_.*")
        .allowlist_type("stat_var_.*")
        .allowlist_type("stat_var")
        .allowlist_function("register_stat2")
        // MI response builders (from mi/item.h)
        .allowlist_type("mi_params_.*")
        .allowlist_type("mi_response_t")
        .allowlist_type("mi_item_t")
        .allowlist_function("init_mi_result_object")
        .allowlist_function("init_mi_result_array")
        .allowlist_function("init_mi_result_string")
        .allowlist_function("init_mi_error_extra")
        .allowlist_function("init_mi_param_error")
        .allowlist_function("free_mi_response")
        .allowlist_function("add_mi_object")
        .allowlist_function("add_mi_array")
        .allowlist_function("add_mi_string")
        .allowlist_function("add_mi_string_fmt")
        .allowlist_function("add_mi_number")
        .allowlist_function("add_mi_bool")
        .allowlist_function("add_mi_null")
        .allowlist_function("get_mi_string_param")
        .allowlist_function("get_mi_int_param")
        .allowlist_function("try_get_mi_string_param")
        .allowlist_function("try_get_mi_int_param")
        .allowlist_type("dep_export_.*")
        .allowlist_type("module_dependency.*")
        .allowlist_type("modparam_dependency.*")
        .allowlist_type("sip_msg")
        .allowlist_type("msg_start")
        .allowlist_type("hdr_field")
        .allowlist_type("receive_info")
        .allowlist_type("ip_addr")
        .allowlist_type("__str")
        .allowlist_type("__str_const")
        .allowlist_type("pv_value_t")
        .allowlist_type("_pv_value")
        .allowlist_type("pv_spec_t")
        .allowlist_type("_pv_spec")
        .allowlist_type("pv_elem.*")
        .allowlist_type("action_elem_.*")
        .allowlist_type("action")
        .allowlist_type("scm_version")
        .allowlist_type("socket_info")
        .allowlist_type("int_str")
        // Async support
        .allowlist_type("acmd_export_.*")
        .allowlist_type("async_ctx")
        .allowlist_type("async_ret_code")
        .allowlist_var("async_status")
        // Allow key functions
        .allowlist_function("pv_parse_format")
        .allowlist_function("pv_printf")
        .allowlist_function("pv_printf_s")
        .allowlist_function("pv_parse_spec")
        .allowlist_function("pv_get_spec_value")
        .allowlist_function("pv_set_value")
        .allowlist_function("pv_elem_free_all")
        .allowlist_function("pv_value_destroy")
        .allowlist_function("pv_spec_free")
        .allowlist_function("fix_cmd")
        .allowlist_function("get_cmd_fixups")
        .allowlist_function("free_cmd_fixups")
        .allowlist_function("find_cmd_export_t")
        .allowlist_function("set_ruri")
        .allowlist_function("set_dst_uri")
        .allowlist_function("reset_dst_uri")
        .allowlist_function("parse_headers")
        .allowlist_function("module_loaded")
        // Dialog module callback types
        .allowlist_type("dlg_cb_params")
        .allowlist_type("dlg_head_cbl")
        .allowlist_type("dlg_callback")
        .allowlist_function("register_dlgcb")
        .allowlist_var("DLGCB_.*")
        // Derive traits
        .derive_debug(true)
        .derive_default(true)
        .derive_copy(true)
        .layout_tests(false)
        .use_core()
        .generate()
        .expect("bindgen failed to generate bindings");

    let sys_rs = out_dir.join("sys.rs");
    bindings
        .write_to_file(&sys_rs)
        .expect("Failed to write sys.rs");

    // Compile C shim with the same flags `OpenSIPS` uses
    let shim_path = Path::new("shim.c");
    if shim_path.exists() {
        let mut build = cc::Build::new();
        build.file("shim.c").include(&src_dir);

        for (name, val) in &dflags {
            match val {
                Some(v) => { build.define(name, v.as_str()); }
                None => { build.define(name, None); }
            }
        }

        build.warnings(false).compile("opensips_shim");
    }

    // Compile test_stubs.c (weak symbol stubs) into a separate archive.
    // These provide stub implementations of OpenSIPS core symbols (dprint,
    // log_level, etc.) so that test binaries can link without the real core.
    //
    // CRITICAL: test_stubs.c must NOT be linked into release cdylib builds.
    //
    // Why: test_stubs.c defines weak function/variable symbols like
    // `gen_shm_malloc`, `shm_block`, `mem_lock` to satisfy the linker when
    // building test harness binaries. But OpenSIPS core's `shm_mem.h`
    // declares `gen_shm_malloc` as an `extern void *(*gen_shm_malloc)(...)` —
    // a function POINTER VARIABLE, not a function. test_stubs.c instead
    // defines it as a FUNCTION. When shim.c (which includes shm_mem.h) is
    // compiled, the call to `shm_malloc()` inlines `_shm_malloc()` which
    // dereferences `gen_shm_malloc` as a pointer variable (double-load).
    //
    // At link time for a release cdylib with `strip = "symbols"` and
    // `lto = true`, the linker:
    //   1. Sees the weak local defn from test_stubs.o as a function,
    //   2. Resolves shim.c's reference to it via R_AARCH64_RELATIVE
    //      pointing at the thunk's code address,
    //   3. Strips the dynamic symbol so OpenSIPS core's strong symbol
    //      cannot override it at dlopen.
    // At runtime, shim.c's `shm_malloc` loads the "pointer value" from
    // the thunk's instruction bytes → x5 = garbage → `blr x5` → SIGSEGV.
    //
    // The fix: only compile test_stubs.c in debug (test) profile. In
    // release, leave `gen_shm_malloc`/`shm_block`/`mem_lock` etc. as
    // undefined dynamic references, resolved at dlopen from the OpenSIPS
    // core binary (which exports them via the main binary's dynsym).
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    let stubs_path = Path::new("test_stubs.c");
    if stubs_path.exists() && profile != "release" {
        println!("cargo:rerun-if-changed=test_stubs.c");
        cc::Build::new()
            .file("test_stubs.c")
            .warnings(false)
            .link_lib_modifier("+whole-archive")
            .compile("opensips_test_stubs");
    }
}

/// Extract -D flags from `OpenSIPS`'s `make -n -B` output.
///
/// This is the key insight: instead of hardcoding, we ask `OpenSIPS`'s
/// own build system what flags it uses, then reuse them verbatim.
fn extract_opensips_dflags(src: &Path) -> Vec<(String, Option<String>)> {
    let output = Command::new("make")
        .arg("-n")
        .arg("-B")
        .current_dir(src)
        .output();

    let stdout = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(e) => {
            eprintln!("cargo:warning=Failed to run make -n -B: {e}");
            return fallback_dflags(src);
        }
    };

    // Find the first cc/gcc line (a compile command)
    let cc_line = stdout
        .lines()
        .find(|l| l.starts_with("cc ") || l.starts_with("gcc "));

    let Some(cc_line) = cc_line else {
        eprintln!("cargo:warning=No cc line found in make -n -B output, using fallback");
        return fallback_dflags(src);
    };

    // Extract all -D flags
    parse_dflags_from_cc_line(cc_line)
}

/// Parse -D flags from a compiler command line.
/// Handles: -DFOO, -DFOO=BAR, -DFOO='"string"', -DFOO='"/path/"'
fn parse_dflags_from_cc_line(line: &str) -> Vec<(String, Option<String>)> {
    let mut flags = Vec::new();
    let mut i = 0;
    let chars: Vec<char> = line.chars().collect();

    while i < chars.len() {
        // Look for -D
        if i + 1 < chars.len() && chars[i] == '-' && chars[i + 1] == 'D' {
            i += 2; // skip -D
            let start = i;

            // Collect until whitespace or end, handling quotes
            let mut in_single_quote = false;
            let mut in_double_quote = false;
            while i < chars.len() {
                match chars[i] {
                    '\'' if !in_double_quote => in_single_quote = !in_single_quote,
                    '"' if !in_single_quote => in_double_quote = !in_double_quote,
                    ' ' | '\t' if !in_single_quote && !in_double_quote => break,
                    _ => {}
                }
                i += 1;
            }

            let token: String = chars[start..i].iter().collect();

            // Split on first '=' to get name and value
            if let Some(eq_pos) = token.find('=') {
                let name = token[..eq_pos].to_string();
                let mut val = token[eq_pos + 1..].to_string();
                // Strip outer single quotes if present
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

/// Fallback: parse defines from `Makefile.conf` if make -n fails.
fn fallback_dflags(src: &Path) -> Vec<(String, Option<String>)> {
    let conf_path = src.join("Makefile.conf");
    let content = if conf_path.exists() {
        fs::read_to_string(&conf_path).unwrap_or_default()
    } else {
        let template = src.join("Makefile.conf.template");
        fs::read_to_string(&template).unwrap_or_default()
    };

    let mut defs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with("DEFS+=") {
            let rhs = line.trim_start_matches("DEFS+=").trim();
            if let Some(name) = rhs.strip_prefix("-D") {
                let name = name.split_whitespace().next().unwrap_or(name);
                if let Some(eq) = name.find('=') {
                    defs.push((name[..eq].to_string(), Some(name[eq + 1..].to_string())));
                } else {
                    defs.push((name.to_string(), None));
                }
            }
        }
    }
    defs
}

/// Parse `VERSION_MAJOR` and `VERSION_MINOR` from `Makefile.defs`
fn parse_version(src: &Path) -> (u32, u32) {
    let content = fs::read_to_string(src.join("Makefile.defs"))
        .expect("Failed to read Makefile.defs");

    let mut major = 0u32;
    let mut minor = 0u32;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("VERSION_MAJOR") && line.contains('=') && !line.contains("$(") {
            if let Some(val) = line.split('=').nth(1) {
                major = val.trim().parse().unwrap_or(0);
            }
        } else if line.starts_with("VERSION_MINOR") && !line.starts_with("VERSION_MINOR_")
            && line.contains('=') && !line.contains("$(")
        {
            if let Some(val) = line.split('=').nth(1) {
                minor = val.trim().parse().unwrap_or(0);
            }
        }
    }

    assert!(major != 0, "Could not parse VERSION_MAJOR from Makefile.defs");

    (major, minor)
}

/// Compile and run a tiny C program to extract `OPENSIPS_FULL_VERSION` and `OPENSIPS_COMPILE_FLAGS`.
/// This ensures the Rust module's version strings match the core exactly.
fn probe_version_strings(src: &Path, dflags: &[(String, Option<String>)]) -> (String, String) {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let probe_src = Path::new("version_probe.c");

    if !probe_src.exists() {
        return ("unknown".to_string(), "unknown".to_string());
    }

    let probe_bin = out_dir.join("version_probe");

    // Build the compiler command with all the same -D flags
    let mut cmd = Command::new("cc");
    cmd.arg("-o").arg(&probe_bin)
       .arg(probe_src)
       .arg(format!("-I{}", src.display()));

    for (name, val) in dflags {
        match val {
            Some(v) => { cmd.arg(format!("-D{name}={v}")); }
            None => { cmd.arg(format!("-D{name}")); }
        }
    }

    let output = cmd.output();
    match output {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            eprintln!("cargo:warning=version_probe compilation failed: {}", String::from_utf8_lossy(&o.stderr));
            return ("unknown".to_string(), "unknown".to_string());
        }
        Err(e) => {
            eprintln!("cargo:warning=Failed to run cc: {e}");
            return ("unknown".to_string(), "unknown".to_string());
        }
    }

    // Run the probe
    let output = Command::new(&probe_bin).output();
    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let mut full_version = String::new();
            let mut compile_flags = String::new();

            for line in stdout.lines() {
                if let Some(v) = line.strip_prefix("FULL_VERSION=") {
                    full_version = v.to_string();
                } else if let Some(v) = line.strip_prefix("COMPILE_FLAGS=") {
                    compile_flags = v.to_string();
                }
            }

            (full_version, compile_flags)
        }
        _ => ("unknown".to_string(), "unknown".to_string()),
    }
}
