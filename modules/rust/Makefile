# Makefile for in-tree OpenSIPS build system integration.
#
# rust.so — the rust_exec() runtime module.
#
# This follows the tls_wolfssl pattern: Cargo produces a static library,
# which the OpenSIPS Makefile links into a .so.
#
# Build:
#   cd /usr/local/src/opensips && make modules modules=modules/rust

include ../../Makefile.defs
auto_gen=
NAME=rust.so

# ── Cargo build ───────────────────────────────────────────────────────
# The workspace root is at modules/Cargo.toml (one level up).
# Target dir is at modules/target/ (shared across all Rust modules).
CARGO := $(shell command -v cargo 2>/dev/null)
OPENSIPS_ROOT=$(shell cd ../.. && pwd)
RUST_TARGET=$(CURDIR)/../target/release
RUST_LIB=$(RUST_TARGET)/libopensips_mod_rust.a

# ── Linking ───────────────────────────────────────────────────────────
LIBS += -Wl,--whole-archive $(RUST_LIB) -Wl,--no-whole-archive \
    -lpthread -ldl -lm -lssl -lcrypto -lgcc_s
DEPS += $(RUST_LIB)

include ../../Makefile.modules

# ── Build the Rust library via Cargo ──────────────────────────────────
RUST_SOURCES = $(wildcard $(CURDIR)/sdk/src/*.rs) \
               $(wildcard $(CURDIR)/src/*.rs) \
               $(CURDIR)/../Cargo.toml \
               $(CURDIR)/sdk/shim.c \
               $(CURDIR)/sdk/bindings.h.in

$(RUST_LIB): $(RUST_SOURCES)
ifndef CARGO
	$(error Rust toolchain not found. Install from https://rustup.rs or add rust to exclude_modules)
endif
	@echo "Building Rust module via Cargo..."
	$(Q)cd $(CURDIR)/.. && \
		OPENSIPS_SRC_DIR=$(OPENSIPS_ROOT) \
		cargo build --release --lib -p opensips-mod-rust
	@echo "Rust static library built: $(RUST_LIB)"

# ── Clean ─────────────────────────────────────────────────────────────
clean: clean-rust

.PHONY: clean-rust
clean-rust:
	-@rm -f $(RUST_LIB)
