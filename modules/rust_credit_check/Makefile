# Makefile for rust_credit_check.so — thin wrapper around Cargo build.
#
# Build:
#   cd /usr/local/src/opensips && make modules modules=modules/rust_credit_check
#
# The .so is built by Cargo (cdylib) and copied to this directory
# so the OpenSIPS install targets can find it.

include ../../Makefile.defs
auto_gen=
NAME=rust_credit_check.so

CARGO := $(shell command -v cargo 2>/dev/null)
OPENSIPS_ROOT=$(shell cd ../.. && pwd)
RUST_TARGET=$(CURDIR)/../target/release

.PHONY: all clean proper install_module_custom

all: $(NAME)

$(NAME):
ifndef CARGO
	$(error Rust toolchain not found. Install from https://rustup.rs or add rust_credit_check to exclude_modules)
endif
	@echo "Building Rust module $(NAME)..."
	@cd $(CURDIR)/.. && \
		OPENSIPS_SRC_DIR=$(OPENSIPS_ROOT) \
		cargo build --release -p $(subst _,-,$(basename $(NAME)))
	@cp $(RUST_TARGET)/librust_credit_check.so $(CURDIR)/$(NAME)
	@echo "$(NAME) built successfully"

clean:
	-@rm -f $(NAME)

proper: clean

install_module_custom:
	@true
