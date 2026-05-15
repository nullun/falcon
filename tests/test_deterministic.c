#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../falcon.h"
#include "../deterministic.h"
#include "test_deterministic_kat.h"

// number of KATs for compressed format
#define NUM_KATS 512
// number of KATs for converting compressed to CT format
#define NUM_KATS_CT 32

// enable in order to regenerate KATs (pipe output to test_deterministic_kat.h)
// #define GENERATE_KATS 1

// Copied from test_falcon.c
static size_t
hextobin(uint8_t *buf, size_t max_len, const char *src)
{
	size_t u;
	int acc, z;

	u = 0;
	acc = 0;
	z = 0;
	for (;;) {
		int c;

		c = *src ++;
		if (c == 0) {
			if (z) {
				fprintf(stderr, "Lone hex nibble\n");
				exit(EXIT_FAILURE);
			}
			return u;
		}
		if (c >= '0' && c <= '9') {
			c -= '0';
		} else if (c >= 'A' && c <= 'F') {
			c -= 'A' - 10;
		} else if (c >= 'a' && c <= 'f') {
			c -= 'a' - 10;
		} else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
			continue;
		} else {
			fprintf(stderr, "Not a hex digit: U+%04X\n",
				(unsigned)c);
			exit(EXIT_FAILURE);
		}
		if (z) {
			if (u >= max_len) {
				fprintf(stderr,
					"Hex string too long for buffer\n");
				exit(EXIT_FAILURE);
			}
			buf[u ++] = (unsigned char)((acc << 4) + c);
		} else {
			acc = c;
		}
		z = !z;
	}
}


/* ---- Instantiate the KAT runner for det1024 ---- */
#define DET_FN(name)                falcon_det1024_##name
#define TEST_FN(name)               name##_det1024
#define DET_DISPLAY_NAME            "FALCON-DET1024"
#define DET_KAT_NAME                "FALCON_DET1024"
#define DET_PUBKEY_SIZE             FALCON_DET1024_PUBKEY_SIZE
#define DET_PRIVKEY_SIZE            FALCON_DET1024_PRIVKEY_SIZE
#define DET_SIG_COMPRESSED_MAXSIZE  FALCON_DET1024_SIG_COMPRESSED_MAXSIZE
#define DET_SIG_CT_SIZE             FALCON_DET1024_SIG_CT_SIZE
#define DET_CURRENT_SALT_VERSION    FALCON_DET1024_CURRENT_SALT_VERSION
#define DET_KAT                     FALCON_DET1024_KAT
#define DET_KAT_CT                  FALCON_DET1024_KAT_CT
#include "test_deterministic_impl.h"


/* ---- Instantiate the KAT runner for det512 ---- */
#define DET_FN(name)                falcon_det512_##name
#define TEST_FN(name)               name##_det512
#define DET_DISPLAY_NAME            "FALCON-DET512"
#define DET_KAT_NAME                "FALCON_DET512"
#define DET_PUBKEY_SIZE             FALCON_DET512_PUBKEY_SIZE
#define DET_PRIVKEY_SIZE            FALCON_DET512_PRIVKEY_SIZE
#define DET_SIG_COMPRESSED_MAXSIZE  FALCON_DET512_SIG_COMPRESSED_MAXSIZE
#define DET_SIG_CT_SIZE             FALCON_DET512_SIG_CT_SIZE
#define DET_CURRENT_SALT_VERSION    FALCON_DET512_CURRENT_SALT_VERSION
#define DET_KAT                     FALCON_DET512_KAT
#define DET_KAT_CT                  FALCON_DET512_KAT_CT
#include "test_deterministic_impl.h"


int main() {
	run_kats_det1024();
	run_kats_det512();

#ifndef GENERATE_KATS
	printf("\nAll known-answer tests (KATs) pass.\n");
#endif
	return 0;
}
