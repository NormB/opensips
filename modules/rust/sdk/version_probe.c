/* Tiny probe program to extract OpenSIPS version strings at build time.
 * Compiled and run by build.rs to get OPENSIPS_FULL_VERSION and
 * OPENSIPS_COMPILE_FLAGS without hardcoding them.
 */
#include <stdio.h>
#include "version.h"

int main(void) {
    printf("FULL_VERSION=%s\n", OPENSIPS_FULL_VERSION);
    printf("COMPILE_FLAGS=%s\n", OPENSIPS_COMPILE_FLAGS);
    return 0;
}
