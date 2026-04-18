# Building the OpenSIPS Rust Module

This guide covers building the Rust module from scratch, whether you're
starting from a bare Debian system, an OpenSIPS Docker container, or an
existing OpenSIPS installation.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Docker: Build from Scratch](#docker-build-from-scratch)
4. [Bare Metal: Step by Step](#bare-metal-step-by-step)
5. [OpenSIPS Make System Integration](#opensips-make-system-integration)
6. [Deploying the Module](#deploying-the-module)
7. [Configuration](#configuration)
8. [Verification](#verification)
9. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

The module ships as a Cargo workspace with two crates:

```
opensips-rust/
  modules/
    rust/
      opensips-rs/         # Reusable SDK (generates FFI bindings, C shim)
      src/                 # Module (rate limiter, cache, HTTP pool)
```

**Why Cargo, not Make?** OpenSIPS's build system compiles C modules using
`make -C modules/<name>`. It discovers `.c` files, compiles them to `.o`,
and links into a `.so`. A Rust module cannot use this directly because:

- Rust code is compiled by `rustc` via Cargo, not `cc`
- The SDK uses `bindgen` to generate FFI bindings at build time
- Dependencies (e.g., `reqwest` for HTTP) are managed by Cargo

We support two build approaches:

| Approach | How | Best for |
|----------|-----|----------|
| **Standalone Cargo** | `cargo build --release` produces the `.so` directly | Development, CI, Docker |
| **In-tree Make** | Symlink into `modules/`, `make modules module=rust` | Production integration |

Both produce an identical `rust.so`.

---

## Prerequisites

### OpenSIPS Source Tree

The Rust module compiles against the OpenSIPS C headers. You need the
**source tree** of the same OpenSIPS version you're running. A package
install (`apt install opensips`) is not sufficient — the headers and
Makefile infrastructure are not included in binary packages.

### Build Dependencies

| Package | Why |
|---------|-----|
| `build-essential` | C compiler, make, linker |
| `pkg-config` | Detect system libraries |
| `libssl-dev` | Required by reqwest (HTTP client) |
| `clang` | Required by bindgen for parsing C headers |
| `llvm-dev` | LLVM libraries for bindgen |
| `libclang-dev` | libclang for bindgen |
| `bison`, `flex` | OpenSIPS parser generators (if building OpenSIPS) |
| `libxml2-dev` | OpenSIPS core dependency |
| `libpcre2-dev` | OpenSIPS regex support |

### Rust Toolchain

Minimum Rust version: **1.70** (for OnceLock stabilization).
Recommended: latest stable via rustup.

---

## Docker: Build from Scratch

The official `opensips/opensips` Docker image installs from `.deb` packages
and does **not** include headers or source. For a Rust module, use a custom
multi-stage Dockerfile that builds everything from source.

### Using the Provided Dockerfile

```bash
# Build the image (includes OpenSIPS + Rust module)
docker build -t opensips-rust .

# Run with a custom config
docker run -v ./modules/rust/doc/opensips.cfg.example:/etc/opensips/opensips.cfg \
    -p 5060:5060/udp opensips-rust
```

### Dockerfile Walkthrough

The provided `Dockerfile` has three stages:

1. **`builder-opensips`** — Clones and builds OpenSIPS from source. This
   produces the binary, module `.so` files, and leaves the source tree
   intact for the Rust module's `bindgen` to use.

2. **`builder-rust`** — Installs the Rust toolchain, copies the module
   source, and runs `cargo build --release`. The build.rs scripts
   automatically detect the OpenSIPS version from the source tree.

3. **`runtime`** — Minimal Debian image with only the OpenSIPS binary,
   core modules, the Rust module, and runtime libraries. No compilers,
   no source code, no Rust toolchain.

### Adding Rust to an Existing OpenSIPS Docker Image

If you already have a Docker image with OpenSIPS built from source,
add these layers:

```dockerfile
# Install Rust build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev clang llvm-dev libclang-dev curl ca-certificates

# Install Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build the module
# OPENSIPS_SRC_DIR must point to the OpenSIPS source tree
COPY opensips-rust/ /build/opensips-rust/
RUN cd /build/opensips-rust \
    && OPENSIPS_SRC_DIR=/usr/local/src/opensips cargo build --release

# Deploy
RUN cp /build/opensips-rust/target/release/libopensips_mod_rust.so \
    /usr/local/lib64/opensips/modules/rust.so
```

Key requirement: `OPENSIPS_SRC_DIR` must point to the same source tree
that produced the running OpenSIPS binary. Version mismatch = module
won't load.

---

## Bare Metal: Step by Step

### Step 1: Build OpenSIPS from Source

Skip this if OpenSIPS is already built and the source tree exists.

```bash
# Install OpenSIPS build dependencies
sudo apt-get update
sudo apt-get install -y build-essential bison flex \
    libxml2-dev libpcre2-dev pkg-config

# Get the source (use the version matching your deployment)
cd /usr/local/src
git clone https://github.com/OpenSIPS/opensips.git
cd opensips
git checkout 3.5  # or master for 4.0-dev

# Build and install
make all
sudo make install

# Verify
/usr/local/sbin/opensips -V
```

The source tree at `/usr/local/src/opensips/` must remain intact — the
Rust module's build system reads `Makefile.defs` and runs `make -n -B`
against it to extract compiler flags.

### Step 2: Install Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustc --version  # should print 1.70.0 or higher
```

### Step 3: Install Rust Module Build Dependencies

```bash
sudo apt-get install -y pkg-config libssl-dev clang llvm-dev libclang-dev
```

These are needed by:
- `bindgen` (clang, llvm-dev, libclang-dev) — parses OpenSIPS C headers
- `reqwest` (libssl-dev, pkg-config) — HTTP client with TLS support

### Step 4: Clone and Build the Module

```bash
git clone git@gitlab-int:gator/opensips-rust.git
cd opensips-rust

# Set the OpenSIPS source path (default: /usr/local/src/opensips)
export OPENSIPS_SRC_DIR=/usr/local/src/opensips

# Build
cargo build --release
```

The build takes ~2-4 minutes on first run (downloads + compiles dependencies).
Subsequent builds take ~10-30 seconds.

### Step 5: Deploy

```bash
# Find your modules directory
MODDIR=$(/usr/local/sbin/opensips -V 2>&1 | grep -oP 'modules.*?/' || echo "/usr/local/lib64/opensips/modules/")
sudo cp target/release/libopensips_mod_rust.so ${MODDIR}rust.so
```

Or use the provided script:

```bash
./scripts/build.sh  # builds and copies to /usr/local/lib64/opensips/modules/
```

---

## OpenSIPS Make System Integration

For production deployments, the module can be integrated into OpenSIPS's
`make modules` system. This follows the same pattern used by
`tls_wolfssl`, which builds an external C library (wolfSSL via autotools)
as a Make dependency.

### How It Works

1. Create `modules/rust/` in the OpenSIPS source tree
2. A `Makefile` there declares the Cargo-built static library as a `DEPS`
3. `make modules module=rust` invokes Cargo, then links the result

### Setup

```bash
./scripts/intree-install.sh /usr/local/src/opensips
```

This creates `modules/rust/` in the OpenSIPS source tree with:
- `Makefile` — build rules that invoke Cargo
- `rust.c` — minimal C stub (required by Makefile.sources)
- `workspace` — symlink to the Cargo workspace root

### Building via Make

```bash
cd /usr/local/src/opensips
make modules module=rust
```

This will:
1. Run `cargo build --release` in the Rust workspace
2. Compile `rust.c` (thin C entry point) with OpenSIPS's flags
3. Link both into `modules/rust/rust.so`

### Installing via Make

```bash
sudo make install-modules module=rust
```

### The In-Tree Makefile Explained

```makefile
include ../../Makefile.defs
auto_gen=
NAME=rust.so

RUST_DIR=$(shell pwd)/rust
RUST_TARGET=$(RUST_DIR)/target/release
RUST_LIB=$(RUST_TARGET)/libopensips_mod_rust.a

# --whole-archive forces the linker to include all symbols from the
# Rust static library, even though nothing in rust.c references
# them. Without this, the `exports` symbol (defined in Rust) would be
# discarded and OpenSIPS could not load the module.
LIBS += -Wl,--whole-archive $(RUST_LIB) -Wl,--no-whole-archive     -lpthread -ldl -lm -lssl -lcrypto -lgcc_s
DEPS += $(RUST_LIB)

# CRITICAL: include Makefile.modules BEFORE defining custom targets.
# Makefile.modules includes Makefile.rules which sets `all` as the
# default target. Custom rules defined above the include would become
# the default goal, causing make to build only the .a (not the .so).
include ../../Makefile.modules

$(RUST_LIB): $(wildcard $(RUST_DIR)/modules/rust/opensips-rs/src/*.rs)
	cd $(RUST_DIR) && OPENSIPS_SRC_DIR=$(shell cd ../.. && pwd) 		cargo build --release --lib -p opensips-mod-rust

clean: clean-rust

.PHONY: clean-rust
clean-rust:
	-@cd $(RUST_DIR) && cargo clean 2>/dev/null
```

### The C Entry Point

`rust.c` is a minimal file that exists only so OpenSIPS's
`Makefile.sources` (which does `$(wildcard *.c)`) finds at least one C
file. The actual module exports are defined in Rust:

```c
/* rust.c — Stub for OpenSIPS make system integration.
 *
 * The real module_exports struct is defined in Rust (lib.rs) and
 * exported as a #[no_mangle] static. This file exists so that
 * Makefile.sources finds a .c file to compile, satisfying the
 * build system's expectations.
 *
 * It compiles to an empty .o that gets linked with the Rust
 * static library into the final rust.so.
 */

/* intentionally empty — all logic lives in Rust */
```

**Note**: The Cargo.toml for
`opensips-mod-rust` must set `crate-type = ["staticlib"]` instead of
`["cdylib"]`. The provided `modules/rust/ directory` shows this change.

---

## Deploying the Module

### Module Path

OpenSIPS looks for modules in its configured `mpath`. Common locations:

| Install method | Module path |
|---------------|-------------|
| Source (`make install`) | `/usr/local/lib64/opensips/modules/` |
| Debian packages | `/usr/lib/x86_64-linux-gnu/opensips/modules/` |
| Docker (official) | `/usr/lib/x86_64-linux-gnu/opensips/modules/` |
| Custom | Set via `mpath` in opensips.cfg |

### File Naming

- Cargo produces: `libopensips_mod_rust.so` (cdylib) or `libopensips_mod_rust.a` (staticlib)
- OpenSIPS expects: `rust.so`
- The `build.sh` script handles the rename automatically

### Permissions

The `.so` file needs to be readable by the OpenSIPS process:

```bash
sudo chmod 644 /usr/local/lib64/opensips/modules/rust.so
```

---

## Configuration

Add to your `opensips.cfg`:

```
# Module path (adjust for your installation)
mpath="/usr/local/lib64/opensips/modules/"

# Load required protocol and signaling modules
loadmodule "proto_udp.so"
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"

# Load the Rust module
loadmodule "rust.so"

# Configure parameters (all optional, shown with defaults)
modparam("rust", "max_rate", 100)        # requests per window
modparam("rust", "window_seconds", 60)   # rate limit window
modparam("rust", "cache_ttl", 300)       # cache entry lifetime
modparam("rust", "http_timeout", 2)      # HTTP timeout in seconds
modparam("rust", "pool_size", 4)         # HTTP connection pool size
```

See `modules/rust/doc/opensips.cfg.example` for a complete working configuration.

---

## Verification

### Config Check

```bash
# Syntax check — verifies the module loads and all functions resolve
/usr/local/sbin/opensips -c -f /path/to/opensips.cfg
```

A successful check prints `config file ok, exiting...`.

### Runtime Check

```bash
# Start OpenSIPS
/usr/local/sbin/opensips -f /path/to/opensips.cfg

# Send a test SIP message
sipsak -s sip:test@127.0.0.1:5060

# Check logs for module output
grep "rust" /var/log/syslog
```

You should see:
```
rust: module initialized (v4.0)
rust: child_init called for rank ...
rust: HTTP connection pool initialized (timeout=2s, pool=4)
```

### Run the Test Suite

```bash
./scripts/test.sh  # builds, deploys, runs opensips -c
```

---

## Troubleshooting

### "module version mismatch"

The module's compiled version strings don't match the running OpenSIPS
binary. This happens when:

- You built the module against a different source tree than the binary
- The source tree was updated but the module wasn't rebuilt

Fix: rebuild the module against the correct source tree:

```bash
export OPENSIPS_SRC_DIR=/path/to/correct/opensips/source
cargo clean && cargo build --release
```

### "cannot open shared object file"

The `.so` is not in the `mpath` directory. Check:

```bash
# What mpath is configured?
grep mpath /path/to/opensips.cfg

# Is the file there?
ls -la /usr/local/lib64/opensips/modules/rust.so
```

### bindgen fails with "clang not found"

```bash
sudo apt-get install clang llvm-dev libclang-dev
```

### "OpenSIPS source not found"

Set `OPENSIPS_SRC_DIR` to point to the OpenSIPS source tree:

```bash
export OPENSIPS_SRC_DIR=/usr/local/src/opensips
```

The directory must contain `Makefile.defs`.

### Cargo build fails with SSL errors

```bash
sudo apt-get install pkg-config libssl-dev
```

### "make -n -B" produces no output

The OpenSIPS source tree needs to have been configured. Run `make` once
(even if it fails) to generate `Makefile.conf`:

```bash
cd /usr/local/src/opensips && make menuconfig  # or just: cp Makefile.conf.template Makefile.conf
```
