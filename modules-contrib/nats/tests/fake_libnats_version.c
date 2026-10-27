/*
 * fake_libnats_version.c -- a stand-in libnats for test_nats_dl's
 * header/runtime version-guard cases.  It exports ONLY
 * nats_GetVersionNumber(), built three ways by tests/Makefile:
 *   fake_libnats_ok.so    -- reports the compiled header's version
 *   fake_libnats_bump.so  -- reports the next minor version (layout drift)
 *   fake_libnats_nover.so -- no nats_GetVersionNumber at all
 */
#include <stdint.h>
#include <nats/nats.h>

#ifndef FAKE_NO_VERSION
uint32_t nats_GetVersionNumber(void)
{
#ifdef FAKE_BUMP_MINOR
	return NATS_VERSION_NUMBER + 0x100;
#else
	return NATS_VERSION_NUMBER;
#endif
}
#else
int fake_libnats_placeholder(void) { return 0; }
#endif
