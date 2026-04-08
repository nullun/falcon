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

// enable in order to generate KATs (pipe output to test_deterministic_kat.h)
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

uint8_t sigs_ct[NUM_KATS][FALCON_DET1024_SIG_CT_SIZE] = {{0}};

void test_inner(size_t data_len) {
	uint8_t pubkey[FALCON_DET1024_PUBKEY_SIZE];
	uint8_t privkey[FALCON_DET1024_PRIVKEY_SIZE];
	uint8_t sig[FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
	uint8_t sig_legacy[FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
	size_t sig_len;
	size_t sig_len_legacy;
	uint8_t expected_sig[FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
	uint8_t data[data_len];
	uint8_t keygen_workbuf[FALCON_DET1024_WORKBUF_KEYGEN_SIZE];
	uint8_t sign_workbuf[FALCON_DET1024_WORKBUF_SIGN_COMPRESSED_SIZE];
	uint8_t verify_comp_workbuf[FALCON_DET1024_WORKBUF_VERIFY_COMPRESSED_SIZE];
	uint8_t verify_ct_workbuf[FALCON_DET1024_WORKBUF_VERIFY_CT_SIZE];
	uint8_t convert_workbuf[FALCON_DET1024_WORKBUF_CONVERT_TO_CT_SIZE];
	uint8_t hash_workbuf[FALCON_DET1024_WORKBUF_HASH_TO_POINT_SIZE];
	uint8_t s1_workbuf[FALCON_DET1024_WORKBUF_S1COEFFS_SIZE];
	uint16_t h[FALCON_DET1024_LOGN ? (1 << FALCON_DET1024_LOGN) : 1];
	uint16_t c[FALCON_DET1024_LOGN ? (1 << FALCON_DET1024_LOGN) : 1];
	int16_t s2[FALCON_DET1024_LOGN ? (1 << FALCON_DET1024_LOGN) : 1];
	int16_t s1[FALCON_DET1024_LOGN ? (1 << FALCON_DET1024_LOGN) : 1];
	int16_t s1_legacy[FALCON_DET1024_LOGN ? (1 << FALCON_DET1024_LOGN) : 1];

	memset(privkey, 0, FALCON_DET1024_PRIVKEY_SIZE);
	memset(pubkey, 0, FALCON_DET1024_PUBKEY_SIZE);

	shake256_context msg_rng;
	char msg_seed[8+1];
	sprintf(msg_seed, "msg-%04zu", data_len);
	shake256_init_prng_from_seed(&msg_rng, msg_seed, 8);
	shake256_extract(&msg_rng, data, data_len);

	shake256_context key_rng;
	char key_seed[8+1];
	sprintf(key_seed, "key-%04zu", data_len);
	shake256_init_prng_from_seed(&key_rng, key_seed, 8);
	int r = falcon_det1024_keygen_with_workbuf(&key_rng, privkey, pubkey,
		keygen_workbuf, sizeof keygen_workbuf);
	if (r != 0) {
		fprintf(stderr, "keygen (data_len=%zu) failed: %d\n", data_len, r);
		exit(EXIT_FAILURE);
	}

	memset(sig, 0, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE);
	r = falcon_det1024_sign_compressed_with_workbuf(sig, &sig_len, privkey,
		data, data_len, sign_workbuf, sizeof sign_workbuf);
	if (r != 0) {
		fprintf(stderr, "sign_compressed (data_len=%zu) failed: %d\n", data_len, r);
		exit(EXIT_FAILURE);
	}

	int v = falcon_det1024_get_salt_version(sig);
	if (v != FALCON_DET1024_CURRENT_SALT_VERSION) {
		fprintf(stderr, "unexpected salt version: %d", v);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_verify_compressed_with_workbuf(sig, sig_len, pubkey,
		data, data_len, verify_comp_workbuf, sizeof verify_comp_workbuf);
	if (r != 0) {
		fprintf(stderr, "verify_compressed (data_len=%zu) failed: %d\n", data_len, r);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_convert_compressed_to_ct_with_workbuf(sigs_ct[data_len],
		sig, sig_len, convert_workbuf, sizeof convert_workbuf);
	if (r != 0) {
		fprintf(stderr, "conversion to CT format (data_len=%zu) failed: %d\n", data_len, r);
		exit(EXIT_FAILURE);
	}

	int vct = falcon_det1024_get_salt_version(sigs_ct[data_len]);
	if (vct != FALCON_DET1024_CURRENT_SALT_VERSION) {
		fprintf(stderr, "unexpected salt version: %d", v);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_verify_ct_with_workbuf(sigs_ct[data_len], pubkey, data,
		data_len, verify_ct_workbuf, sizeof verify_ct_workbuf);
	if (r != 0) {
		fprintf(stderr, "verify_ct (data_len=%zu) failed: %d\n", data_len, r);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_pubkey_coeffs(h, pubkey);
	if (r != 0) {
		fprintf(stderr, "pubkey_coeffs (data_len=%zu) failed: %d\n", data_len, r);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_hash_to_point_coeffs_with_workbuf(c, data, data_len, v,
		hash_workbuf, sizeof hash_workbuf);
	if (r != 0) {
		fprintf(stderr, "hash_to_point (data_len=%zu) failed: %d\n", data_len, r);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_s2_coeffs(s2, sigs_ct[data_len]);
	if (r != 0) {
		fprintf(stderr, "s2_coeffs (data_len=%zu) failed: %d\n", data_len, r);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_s1_coeffs_with_workbuf(s1, h, c, s2,
		s1_workbuf, sizeof s1_workbuf);
	if (r != 0) {
		fprintf(stderr, "s1_coeffs_with_workbuf (data_len=%zu) failed: %d\n", data_len, r);
		exit(EXIT_FAILURE);
	}

	r = falcon_det1024_s1_coeffs(s1_legacy, h, c, s2);
	if (r != 0) {
		fprintf(stderr, "s1_coeffs (data_len=%zu) failed: %d\n", data_len, r);
		exit(EXIT_FAILURE);
	}
	if (memcmp(s1, s1_legacy, sizeof s1) != 0) {
		fprintf(stderr, "s1_coeffs mismatch (data_len=%zu)\n", data_len);
		exit(EXIT_FAILURE);
	}

	if (data_len == 0) {
		uint8_t privkey_legacy[FALCON_DET1024_PRIVKEY_SIZE];
		uint8_t pubkey_legacy[FALCON_DET1024_PUBKEY_SIZE];
		shake256_context key_rng_legacy;

		shake256_init_prng_from_seed(&key_rng_legacy, key_seed, 8);
		r = falcon_det1024_keygen(&key_rng_legacy, privkey_legacy, pubkey_legacy);
		if (r != 0) {
			fprintf(stderr, "legacy keygen failed: %d\n", r);
			exit(EXIT_FAILURE);
		}
		if (memcmp(privkey, privkey_legacy, sizeof privkey) != 0
			|| memcmp(pubkey, pubkey_legacy, sizeof pubkey) != 0)
		{
			fprintf(stderr, "legacy keygen mismatch\n");
			exit(EXIT_FAILURE);
		}

		r = falcon_det1024_sign_compressed(sig_legacy, &sig_len_legacy,
			privkey, data, data_len);
		if (r != 0) {
			fprintf(stderr, "legacy sign failed: %d\n", r);
			exit(EXIT_FAILURE);
		}
		if (sig_len != sig_len_legacy
			|| memcmp(sig, sig_legacy, sig_len) != 0)
		{
			fprintf(stderr, "legacy sign mismatch\n");
			exit(EXIT_FAILURE);
		}
	}

#ifdef GENERATE_KATS            /* print the KAT */
	printf("\t\"");
	for (int i = 0; i < sig_len; i++) {
		printf("%02x", sig[i]);
	}
	printf("\",\n");
#else  /* compare to the KAT */
	size_t elen = hextobin(expected_sig, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE, FALCON_DET1024_KAT[data_len]);
	if (elen != sig_len) {
		fprintf(stderr, "sign_compressed (data_len=%zu) length %zu does not match KAT length %zu\n", data_len, sig_len, elen);
		exit(EXIT_FAILURE);
	}
	if (memcmp(sig, expected_sig, sig_len) != 0) {
		fprintf(stderr, "sign_compressed (data_len=%zu) does not match KAT\n", data_len);
		exit(EXIT_FAILURE);
	}
#endif
}

int main() {
#ifdef GENERATE_KATS
	printf("\nstatic const char *const FALCON_DET1024_KAT[] = {\n");
#endif

	for (int kat = 0; kat < NUM_KATS; kat++) {
		test_inner(kat);
#ifndef GENERATE_KATS
		printf(".");
		fflush(stdout);
#endif
	}

#ifdef GENERATE_KATS
	printf("};\n\n");
	printf("\nstatic const char *const FALCON_DET1024_KAT_CT[] = {\n");
	for (int kat = 0; kat < NUM_KATS_CT; kat++) {
		printf("\t\"");
		for (int i = 0; i < FALCON_DET1024_SIG_CT_SIZE; i++) {
			printf("%02x", sigs_ct[kat][i]);
		}
		printf("\",\n");
	}
	printf("};\n\n");
#else
	uint8_t expected_sig_ct[FALCON_DET1024_SIG_CT_SIZE];
	for (int kat = 0; kat < NUM_KATS_CT; kat++) {
		hextobin(expected_sig_ct, FALCON_DET1024_SIG_CT_SIZE, FALCON_DET1024_KAT_CT[kat]);
		if (memcmp(sigs_ct[kat], expected_sig_ct, FALCON_DET1024_SIG_CT_SIZE) != 0) {
			fprintf(stderr, "convert_compressed_to_ct (data_len=%d) does not match KAT\n", kat);
			exit(EXIT_FAILURE);
		}
	}

	printf("\nAll known-answer tests (KATs) pass.\n");
#endif
}
