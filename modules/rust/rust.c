/* rust.c — Stub for OpenSIPS make system integration.
 *
 * The real module_exports struct is defined in Rust (lib.rs) and
 * exported as a #[no_mangle] static symbol. This file exists so that
 * OpenSIPS's Makefile.sources (which does $(wildcard *.c)) finds at
 * least one C file to compile, satisfying the build system's
 * expectations.
 *
 * The compiled rust.o is effectively empty. The linker combines
 * it with the Rust static library (libopensips_mod_rust.a) to produce
 * the final rust.so.
 */

/* intentionally empty — all logic lives in Rust */
