/*
 * Portable known-answer test tool for deterministic Falcon.
 *
 * The KAT arrays compiled into test_deterministic512.c and
 * test_deterministic1024.c derive each private key by running this
 * implementation's own key generator over a seeded PRNG. No other
 * implementation can reproduce that, because the number and order of PRNG
 * draws made by keygen is implementation-specific. Those vectors therefore
 * cannot be used to check a port in another language.
 *
 * This tool re-exports the same vectors in a self-contained, language-neutral
 * form: every record carries the private key, public key and message as
 * literal bytes, so a consumer needs only a signer and a verifier, never a
 * matching key generator.
 *
 * Subcommands:
 *
 *   gen <512|1024> <core|full>
 *       Write a KAT file to stdout. Every emitted signature is cross-checked
 *       against the committed C KAT headers first, so a portable file cannot
 *       disagree with the vectors the existing test programs already enforce.
 *
 *   check <file>
 *       Read a KAT file back, and for each record re-sign the stored message
 *       under the stored private key, transcode to CT format, and verify both
 *       signature forms against the stored public key. This exercises exactly
 *       the path a port in another language takes, so a failure here means the
 *       file is wrong rather than the port.
 *
 * See kat/README.md for the file format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../falcon.h"
#include "../deterministic.h"
#include "test_deterministic512_kat.h"
#include "test_deterministic1024_kat.h"

#define KAT_FORMAT_VERSION 1

/* Number of message lengths exercised by the committed KAT arrays. */
#define NUM_KATS     512
/* Number of leading records for which committed CT-format KATs exist. */
#define NUM_KATS_CT  32

/* Upper bounds across both parameter sets (det1024 is the larger). */
#define MAX_PRIVKEY_SIZE   FALCON_DET1024_PRIVKEY_SIZE
#define MAX_PUBKEY_SIZE    FALCON_DET1024_PUBKEY_SIZE
#define MAX_SIG_SIZE       FALCON_DET1024_SIG_COMPRESSED_MAXSIZE
#define MAX_SIG_CT_SIZE    FALCON_DET1024_SIG_CT_SIZE
/* CT-format signatures are longer than compressed ones, so a buffer that must
   hold either form is sized off the CT constant. */
#define MAX_ANY_SIG_SIZE   FALCON_DET1024_SIG_CT_SIZE
#define MAX_N              1024
#define MAX_MSG_SIZE       4096

/*
 * Message lengths selected for the "core" file: small values, powers of two
 * and their neighbours, the SHAKE256 rate boundary at 136 bytes, and the top
 * of the range. Ports run against this set; the full set is for exhaustive
 * checks.
 */
static const int CORE_LENGTHS[] = {
	0, 1, 2, 3, 4, 5, 7, 8,
	15, 16, 31, 32, 63, 64,
	100, 127, 128, 135, 136, 137,
	200, 255, 256, 300,
	383, 384, 400, 447, 448,
	500, 510, 511
};
#define NUM_CORE_LENGTHS ((int)(sizeof CORE_LENGTHS / sizeof CORE_LENGTHS[0]))

/* ------------------------------------------------------------------ */
/* Hex helpers                                                         */
/* ------------------------------------------------------------------ */

static size_t
hextobin(uint8_t *buf, size_t max_len, const char *src)
{
	size_t u = 0;
	int acc = 0, z = 0;

	for (;;) {
		int c = *src ++;
		if (c == 0) {
			if (z) {
				fprintf(stderr, "lone hex nibble\n");
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
			fprintf(stderr, "not a hex digit: U+%04X\n", (unsigned)c);
			exit(EXIT_FAILURE);
		}
		if (z) {
			if (u >= max_len) {
				fprintf(stderr, "hex string too long for buffer\n");
				exit(EXIT_FAILURE);
			}
			buf[u ++] = (uint8_t)((acc << 4) + c);
		} else {
			acc = c;
		}
		z = !z;
	}
}

static void
print_hex(const uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i ++) {
		printf("%02x", buf[i]);
	}
}

/*
 * Coefficient vectors are written as little-endian 16-bit words so that a
 * consumer can decode them with the same byte-oriented reader it uses for
 * every other field. Signed values use two's complement.
 */
static void
print_coeffs_u16(const uint16_t *v, size_t n)
{
	for (size_t i = 0; i < n; i ++) {
		printf("%02x%02x", v[i] & 0xFF, (v[i] >> 8) & 0xFF);
	}
}

static void
print_coeffs_i16(const int16_t *v, size_t n)
{
	for (size_t i = 0; i < n; i ++) {
		uint16_t w = (uint16_t)v[i];
		printf("%02x%02x", w & 0xFF, (w >> 8) & 0xFF);
	}
}

/* ------------------------------------------------------------------ */
/* Parameter-set dispatch                                              */
/* ------------------------------------------------------------------ */

typedef struct {
	const char *name;
	unsigned logn;
	size_t privkey_size;
	size_t pubkey_size;
	size_t sig_ct_size;
	size_t sig_compressed_maxsize;
	uint8_t salt_version;
	const char *const *kat_compressed;
	const char *const *kat_ct;

	int (*keygen)(shake256_context *rng, void *privkey, void *pubkey);
	int (*sign_compressed)(void *sig, size_t *sig_len,
		const void *privkey, const void *data, size_t data_len);
	int (*verify_compressed)(const void *sig, size_t sig_len,
		const void *pubkey, const void *data, size_t data_len);
	int (*verify_ct)(const void *sig,
		const void *pubkey, const void *data, size_t data_len);
	int (*convert_compressed_to_ct)(void *sig_ct,
		const void *sig_compressed, size_t sig_compressed_len);
	int (*get_salt_version)(const void *sig);
	int (*pubkey_coeffs)(uint16_t *h, const void *pubkey);
	void (*hash_to_point_coeffs)(uint16_t *c,
		const void *data, size_t data_len, uint8_t salt_version);
	int (*s2_coeffs)(int16_t *s2, const void *sig);
	int (*s1_coeffs)(int16_t *s1,
		const uint16_t *h, const uint16_t *c, const int16_t *s2);
} det_params;

static const det_params PARAMS_512 = {
	"FALCON-DET512", FALCON_DET512_LOGN,
	FALCON_DET512_PRIVKEY_SIZE, FALCON_DET512_PUBKEY_SIZE,
	FALCON_DET512_SIG_CT_SIZE, FALCON_DET512_SIG_COMPRESSED_MAXSIZE,
	FALCON_DET512_CURRENT_SALT_VERSION,
	FALCON_DET512_KAT, FALCON_DET512_KAT_CT,
	&falcon_det512_keygen, &falcon_det512_sign_compressed,
	&falcon_det512_verify_compressed, &falcon_det512_verify_ct,
	&falcon_det512_convert_compressed_to_ct, &falcon_det512_get_salt_version,
	&falcon_det512_pubkey_coeffs, &falcon_det512_hash_to_point_coeffs,
	&falcon_det512_s2_coeffs, &falcon_det512_s1_coeffs
};

static const det_params PARAMS_1024 = {
	"FALCON-DET1024", FALCON_DET1024_LOGN,
	FALCON_DET1024_PRIVKEY_SIZE, FALCON_DET1024_PUBKEY_SIZE,
	FALCON_DET1024_SIG_CT_SIZE, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE,
	FALCON_DET1024_CURRENT_SALT_VERSION,
	FALCON_DET1024_KAT, FALCON_DET1024_KAT_CT,
	&falcon_det1024_keygen, &falcon_det1024_sign_compressed,
	&falcon_det1024_verify_compressed, &falcon_det1024_verify_ct,
	&falcon_det1024_convert_compressed_to_ct, &falcon_det1024_get_salt_version,
	&falcon_det1024_pubkey_coeffs, &falcon_det1024_hash_to_point_coeffs,
	&falcon_det1024_s2_coeffs, &falcon_det1024_s1_coeffs
};

/* ------------------------------------------------------------------ */
/* Generation                                                          */
/* ------------------------------------------------------------------ */

/*
 * Reproduce the key and message for one record exactly as
 * tests/test_deterministic<n>.c does, so that the exported vectors are the
 * same ones the committed KAT arrays pin down.
 */
static void
derive_inputs(const det_params *p, int idx,
	uint8_t *privkey, uint8_t *pubkey, uint8_t *msg)
{
	shake256_context msg_rng, key_rng;
	char seed[8 + 1];

	sprintf(seed, "msg-%04d", idx);
	shake256_init_prng_from_seed(&msg_rng, seed, 8);
	shake256_extract(&msg_rng, msg, (size_t)idx);

	sprintf(seed, "key-%04d", idx);
	shake256_init_prng_from_seed(&key_rng, seed, 8);
	if (p->keygen(&key_rng, privkey, pubkey) != 0) {
		fprintf(stderr, "keygen failed at record %d\n", idx);
		exit(EXIT_FAILURE);
	}
}

static void
emit_record(const det_params *p, int idx, int with_checkpoints)
{
	uint8_t privkey[MAX_PRIVKEY_SIZE];
	uint8_t pubkey[MAX_PUBKEY_SIZE];
	uint8_t msg[MAX_MSG_SIZE];
	uint8_t sig[MAX_SIG_SIZE];
	uint8_t sig_ct[MAX_SIG_CT_SIZE];
	uint8_t expected[MAX_ANY_SIG_SIZE];
	size_t sig_len;
	size_t n = (size_t)1 << p->logn;

	derive_inputs(p, idx, privkey, pubkey, msg);

	if (p->sign_compressed(sig, &sig_len, privkey, msg, (size_t)idx) != 0) {
		fprintf(stderr, "sign failed at record %d\n", idx);
		exit(EXIT_FAILURE);
	}

	/*
	 * Cross-check against the committed C KAT before exporting, so the
	 * portable file can only ever agree with them.
	 */
	size_t elen = hextobin(expected, sizeof expected, p->kat_compressed[idx]);
	if (elen != sig_len || memcmp(sig, expected, sig_len) != 0) {
		fprintf(stderr, "record %d disagrees with the committed KAT\n", idx);
		exit(EXIT_FAILURE);
	}

	if (p->convert_compressed_to_ct(sig_ct, sig, sig_len) != 0) {
		fprintf(stderr, "CT conversion failed at record %d\n", idx);
		exit(EXIT_FAILURE);
	}
	if (idx < NUM_KATS_CT) {
		hextobin(expected, sizeof expected, p->kat_ct[idx]);
		if (memcmp(sig_ct, expected, p->sig_ct_size) != 0) {
			fprintf(stderr,
				"record %d CT form disagrees with the committed KAT\n", idx);
			exit(EXIT_FAILURE);
		}
	}

	printf("count = %d\n", idx);
	printf("salt_version = %d\n", p->get_salt_version(sig));
	printf("msg_len = %d\n", idx);
	printf("privkey = "); print_hex(privkey, p->privkey_size); printf("\n");
	printf("pubkey = "); print_hex(pubkey, p->pubkey_size); printf("\n");
	printf("msg = "); print_hex(msg, (size_t)idx); printf("\n");
	printf("sig_compressed = "); print_hex(sig, sig_len); printf("\n");
	printf("sig_ct = "); print_hex(sig_ct, p->sig_ct_size); printf("\n");

	if (with_checkpoints) {
		uint16_t h[MAX_N], c[MAX_N];
		int16_t s1[MAX_N], s2[MAX_N];

		if (p->pubkey_coeffs(h, pubkey) != 0) {
			fprintf(stderr, "pubkey decode failed at record %d\n", idx);
			exit(EXIT_FAILURE);
		}
		p->hash_to_point_coeffs(c, msg, (size_t)idx, p->salt_version);
		/* s2_coeffs accepts only CT-format signatures. */
		if (p->s2_coeffs(s2, sig_ct) != 0) {
			fprintf(stderr, "s2 decode failed at record %d\n", idx);
			exit(EXIT_FAILURE);
		}
		if (p->s1_coeffs(s1, h, c, s2) != 0) {
			fprintf(stderr, "s1 recovery failed at record %d\n", idx);
			exit(EXIT_FAILURE);
		}

		printf("c = "); print_coeffs_u16(c, n); printf("\n");
		printf("s2 = "); print_coeffs_i16(s2, n); printf("\n");
		printf("s1 = "); print_coeffs_i16(s1, n); printf("\n");
	}

	printf("\n");
}

static void
cmd_gen(const det_params *p, int full)
{
	int records = full ? NUM_KATS : NUM_CORE_LENGTHS;

	printf("# %s known-answer tests (portable format)\n", p->name);
	printf("#\n");
	printf("# Generated by tests/kat_tool from the algorand/falcon\n");
	printf("# implementation. Do not edit by hand; see kat/README.md for the\n");
	printf("# format definition and kat/Makefile for regeneration.\n");
	printf("#\n");
	printf("# Every record is self-contained: it carries the private key,\n");
	printf("# public key and message as literal bytes, so reproducing it needs\n");
	printf("# only a signer, never a matching key generator.\n");
	printf("\n");
	printf("alg = %s\n", p->name);
	printf("format_version = %d\n", KAT_FORMAT_VERSION);
	printf("logn = %u\n", p->logn);
	printf("n = %u\n", 1u << p->logn);
	printf("privkey_len = %zu\n", p->privkey_size);
	printf("pubkey_len = %zu\n", p->pubkey_size);
	printf("sig_ct_len = %zu\n", p->sig_ct_size);
	printf("sig_compressed_maxlen = %zu\n", p->sig_compressed_maxsize);
	printf("records = %d\n", records);
	printf("checkpoints = %s\n", full ? "no" : "yes");
	printf("\n");

	if (full) {
		for (int i = 0; i < NUM_KATS; i ++) {
			emit_record(p, i, 0);
		}
	} else {
		for (int i = 0; i < NUM_CORE_LENGTHS; i ++) {
			emit_record(p, CORE_LENGTHS[i], 1);
		}
	}
}

/* ------------------------------------------------------------------ */
/* Checking                                                            */
/* ------------------------------------------------------------------ */

/*
 * Longest line is the private key of det1024 (2305 bytes, 4610 hex digits)
 * or a coefficient vector (1024 words, 4096 hex digits), plus the key name.
 */
#define LINE_MAX 32768

typedef struct {
	int have;
	int count;
	int salt_version;
	size_t msg_len;
	uint8_t privkey[MAX_PRIVKEY_SIZE];
	size_t privkey_len;
	uint8_t pubkey[MAX_PUBKEY_SIZE];
	size_t pubkey_len;
	uint8_t msg[MAX_MSG_SIZE];
	uint8_t sig[MAX_SIG_SIZE];
	size_t sig_len;
	uint8_t sig_ct[MAX_SIG_CT_SIZE];
	size_t sig_ct_len;
	int have_checkpoints;
	uint16_t c[MAX_N];
	int16_t s1[MAX_N];
	int16_t s2[MAX_N];
} kat_record;

static void
decode_coeffs_u16(uint16_t *dst, size_t n, const char *hex, const char *what)
{
	uint8_t raw[MAX_N * 2];
	size_t len = hextobin(raw, sizeof raw, hex);
	if (len != n * 2) {
		fprintf(stderr, "%s: expected %zu bytes, got %zu\n", what, n * 2, len);
		exit(EXIT_FAILURE);
	}
	for (size_t i = 0; i < n; i ++) {
		dst[i] = (uint16_t)(raw[2 * i] | ((uint16_t)raw[2 * i + 1] << 8));
	}
}

static void
decode_coeffs_i16(int16_t *dst, size_t n, const char *hex, const char *what)
{
	uint16_t tmp[MAX_N];
	decode_coeffs_u16(tmp, n, hex, what);
	for (size_t i = 0; i < n; i ++) {
		dst[i] = (int16_t)tmp[i];
	}
}

static void
check_record(const det_params *p, const kat_record *r)
{
	uint8_t sig[MAX_SIG_SIZE];
	uint8_t sig_ct[MAX_SIG_CT_SIZE];
	size_t sig_len;
	size_t n = (size_t)1 << p->logn;

	if (r->privkey_len != p->privkey_size) {
		fprintf(stderr, "record %d: private key length %zu, expected %zu\n",
			r->count, r->privkey_len, p->privkey_size);
		exit(EXIT_FAILURE);
	}
	if (r->pubkey_len != p->pubkey_size) {
		fprintf(stderr, "record %d: public key length %zu, expected %zu\n",
			r->count, r->pubkey_len, p->pubkey_size);
		exit(EXIT_FAILURE);
	}
	if (r->sig_ct_len != p->sig_ct_size) {
		fprintf(stderr, "record %d: CT signature length %zu, expected %zu\n",
			r->count, r->sig_ct_len, p->sig_ct_size);
		exit(EXIT_FAILURE);
	}

	/* Deterministic signing must reproduce the stored signature exactly. */
	if (p->sign_compressed(sig, &sig_len,
		r->privkey, r->msg, r->msg_len) != 0)
	{
		fprintf(stderr, "record %d: signing failed\n", r->count);
		exit(EXIT_FAILURE);
	}
	if (sig_len != r->sig_len || memcmp(sig, r->sig, sig_len) != 0) {
		fprintf(stderr, "record %d: signature does not match\n", r->count);
		exit(EXIT_FAILURE);
	}
	if (p->get_salt_version(sig) != r->salt_version) {
		fprintf(stderr, "record %d: salt version does not match\n", r->count);
		exit(EXIT_FAILURE);
	}

	if (p->convert_compressed_to_ct(sig_ct, r->sig, r->sig_len) != 0) {
		fprintf(stderr, "record %d: CT conversion failed\n", r->count);
		exit(EXIT_FAILURE);
	}
	if (memcmp(sig_ct, r->sig_ct, p->sig_ct_size) != 0) {
		fprintf(stderr, "record %d: CT signature does not match\n", r->count);
		exit(EXIT_FAILURE);
	}

	/* Both stored forms must verify under the stored public key. */
	if (p->verify_compressed(r->sig, r->sig_len,
		r->pubkey, r->msg, r->msg_len) != 0)
	{
		fprintf(stderr, "record %d: compressed signature does not verify\n",
			r->count);
		exit(EXIT_FAILURE);
	}
	if (p->verify_ct(r->sig_ct, r->pubkey, r->msg, r->msg_len) != 0) {
		fprintf(stderr, "record %d: CT signature does not verify\n", r->count);
		exit(EXIT_FAILURE);
	}

	if (r->have_checkpoints) {
		uint16_t h[MAX_N], c[MAX_N];
		int16_t s1[MAX_N], s2[MAX_N];

		if (p->pubkey_coeffs(h, r->pubkey) != 0) {
			fprintf(stderr, "record %d: public key decode failed\n", r->count);
			exit(EXIT_FAILURE);
		}
		p->hash_to_point_coeffs(c, r->msg, r->msg_len, (uint8_t)r->salt_version);
		if (memcmp(c, r->c, n * sizeof *c) != 0) {
			fprintf(stderr, "record %d: hash-to-point does not match\n",
				r->count);
			exit(EXIT_FAILURE);
		}
		if (p->s2_coeffs(s2, r->sig_ct) != 0) {
			fprintf(stderr, "record %d: s2 decode failed\n", r->count);
			exit(EXIT_FAILURE);
		}
		if (memcmp(s2, r->s2, n * sizeof *s2) != 0) {
			fprintf(stderr, "record %d: s2 does not match\n", r->count);
			exit(EXIT_FAILURE);
		}
		if (p->s1_coeffs(s1, h, c, s2) != 0) {
			fprintf(stderr, "record %d: s1 recovery failed\n", r->count);
			exit(EXIT_FAILURE);
		}
		if (memcmp(s1, r->s1, n * sizeof *s1) != 0) {
			fprintf(stderr, "record %d: s1 does not match\n", r->count);
			exit(EXIT_FAILURE);
		}
	}
}

static void
cmd_check(const char *path)
{
	FILE *f;
	static char line[LINE_MAX];
	const det_params *p = NULL;
	static kat_record r;
	size_t n = 0;
	int nrec = 0;

	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "cannot open %s\n", path);
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof line, f) != NULL) {
		char *key, *val, *eq, *e;

		/* Strip the newline; reject a line that did not fit. */
		e = strchr(line, '\n');
		if (e == NULL && !feof(f)) {
			fprintf(stderr, "line too long\n");
			exit(EXIT_FAILURE);
		}
		if (e != NULL) {
			*e = 0;
		}

		key = line;
		while (*key == ' ' || *key == '\t') {
			key ++;
		}
		if (*key == 0 || *key == '#') {
			continue;
		}
		eq = strchr(key, '=');
		if (eq == NULL) {
			fprintf(stderr, "malformed line: %s\n", key);
			exit(EXIT_FAILURE);
		}
		val = eq + 1;
		while (*val == ' ' || *val == '\t') {
			val ++;
		}
		/* Trim trailing whitespace from the key. */
		e = eq;
		while (e > key && (e[-1] == ' ' || e[-1] == '\t')) {
			e --;
		}
		*e = 0;

		if (strcmp(key, "alg") == 0) {
			if (strcmp(val, PARAMS_512.name) == 0) {
				p = &PARAMS_512;
			} else if (strcmp(val, PARAMS_1024.name) == 0) {
				p = &PARAMS_1024;
			} else {
				fprintf(stderr, "unknown algorithm: %s\n", val);
				exit(EXIT_FAILURE);
			}
			n = (size_t)1 << p->logn;
			continue;
		}
		if (strcmp(key, "format_version") == 0) {
			if (atoi(val) != KAT_FORMAT_VERSION) {
				fprintf(stderr, "unsupported format version: %s\n", val);
				exit(EXIT_FAILURE);
			}
			continue;
		}
		/* Remaining header fields are redundant with the algorithm name. */
		if (strcmp(key, "logn") == 0 || strcmp(key, "n") == 0
			|| strcmp(key, "privkey_len") == 0
			|| strcmp(key, "pubkey_len") == 0
			|| strcmp(key, "sig_ct_len") == 0
			|| strcmp(key, "sig_compressed_maxlen") == 0
			|| strcmp(key, "records") == 0
			|| strcmp(key, "checkpoints") == 0)
		{
			continue;
		}

		if (p == NULL) {
			fprintf(stderr, "record field '%s' before the algorithm name\n",
				key);
			exit(EXIT_FAILURE);
		}

		if (strcmp(key, "count") == 0) {
			if (r.have) {
				check_record(p, &r);
				nrec ++;
			}
			memset(&r, 0, sizeof r);
			r.have = 1;
			r.count = atoi(val);
		} else if (strcmp(key, "salt_version") == 0) {
			r.salt_version = atoi(val);
		} else if (strcmp(key, "msg_len") == 0) {
			r.msg_len = (size_t)atoi(val);
		} else if (strcmp(key, "privkey") == 0) {
			r.privkey_len = hextobin(r.privkey, sizeof r.privkey, val);
		} else if (strcmp(key, "pubkey") == 0) {
			r.pubkey_len = hextobin(r.pubkey, sizeof r.pubkey, val);
		} else if (strcmp(key, "msg") == 0) {
			size_t len = hextobin(r.msg, sizeof r.msg, val);
			if (len != r.msg_len) {
				fprintf(stderr,
					"record %d: msg is %zu bytes, msg_len says %zu\n",
					r.count, len, r.msg_len);
				exit(EXIT_FAILURE);
			}
		} else if (strcmp(key, "sig_compressed") == 0) {
			r.sig_len = hextobin(r.sig, sizeof r.sig, val);
		} else if (strcmp(key, "sig_ct") == 0) {
			r.sig_ct_len = hextobin(r.sig_ct, sizeof r.sig_ct, val);
		} else if (strcmp(key, "c") == 0) {
			decode_coeffs_u16(r.c, n, val, "c");
			r.have_checkpoints = 1;
		} else if (strcmp(key, "s1") == 0) {
			decode_coeffs_i16(r.s1, n, val, "s1");
		} else if (strcmp(key, "s2") == 0) {
			decode_coeffs_i16(r.s2, n, val, "s2");
		} else {
			fprintf(stderr, "unknown field: %s\n", key);
			exit(EXIT_FAILURE);
		}
	}
	fclose(f);

	if (r.have) {
		check_record(p, &r);
		nrec ++;
	}
	if (p == NULL || nrec == 0) {
		fprintf(stderr, "%s contains no records\n", path);
		exit(EXIT_FAILURE);
	}

	printf("%s: all %d records of %s check out.\n", path, nrec, p->name);
}

/* ------------------------------------------------------------------ */

static void
usage(void)
{
	fprintf(stderr,
		"usage:\n"
		"  kat_tool gen <512|1024> <core|full>   write a KAT file to stdout\n"
		"  kat_tool check <file>                 re-derive and check a KAT file\n");
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	if (argc < 2) {
		usage();
	}
	if (strcmp(argv[1], "gen") == 0) {
		const det_params *p;
		int full;

		if (argc != 4) {
			usage();
		}
		if (strcmp(argv[2], "512") == 0) {
			p = &PARAMS_512;
		} else if (strcmp(argv[2], "1024") == 0) {
			p = &PARAMS_1024;
		} else {
			usage();
			return EXIT_FAILURE;
		}
		if (strcmp(argv[3], "core") == 0) {
			full = 0;
		} else if (strcmp(argv[3], "full") == 0) {
			full = 1;
		} else {
			usage();
			return EXIT_FAILURE;
		}
		cmd_gen(p, full);
	} else if (strcmp(argv[1], "check") == 0) {
		if (argc != 3) {
			usage();
		}
		cmd_check(argv[2]);
	} else {
		usage();
	}
	return EXIT_SUCCESS;
}
