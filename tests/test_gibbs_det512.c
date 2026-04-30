/*
 * Integration test: Gibbs sampler keygen → det512 sign/verify pipeline.
 *
 * Requires FALCON_GIBBS_KEYGEN to be defined at compile time.  Exercises
 * the full deterministic-Falcon-512 path (compressed and CT) with keys
 * produced by the Gibbs trapdoor sampler (Sun et al., PQCrypto 2026).
 *
 * Also covers the MCU workbuf API variants of keygen, sign, and verify to
 * confirm the det512-mcu-improvements layer works with Gibbs-generated keys.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../deterministic512.h"
#include "../inner.h"

#ifndef FALCON_GIBBS_KEYGEN
#error "FALCON_GIBBS_KEYGEN must be defined to build this test"
#endif

/* Enable to regenerate KAT vectors (pipe stdout into kats below). */
/* #define GENERATE_KATS 1 */

#define TRIALS         3
#define MSG_LEN       32
#define GIBBS_LOGN     9
#define GIBBS_N       (1 << GIBBS_LOGN)

static const char *MSG_SEED = "gibbs-det512-test-msg";
static const char *KEY_SEED = "gibbs-det512-test-key";

/* ================================================================== */
/* KAT vectors (generated with FALCON_FPEMU=1, clang -O3, x86_64).   */
/* ================================================================== */
#ifndef GENERATE_KATS
static const char *const GIBBS_DET512_KAT[] = {
	"b90096f0a9a35cd4accd3c7bdae557fcaa27fe322d9a4b1c09403a640f72bd7c374c14113353ab9397fea7017a942bf49387c25cb3cdab43f0d9a66e3fd774a734d95c8e1ba8cab36220e32490bf020e765af9ce17c1e731aa3b14de1efd4c97b2e8e861d91b9ecd4dceafa54b5a9b445c1aea3a94aac9d1687fe3c8c101997dba385b0cda71eda1683496c4ea1f94f8c4f8289f394383b0b1bcf4c4d4e9b388420284356f75066c9ed571b5219caf23ac6ee2271a48d107a5573175fe039ff680c5f63fdc64192b9525098f26f3d2363bdd798fcdf809045e745c9f1e64f61ecdc63ab406cdad60fc6a019dce7aec3da6d1c0c543314c8b6ba0759d4687e592c9a5857f37de444ccfe98d4aee55bd4a0dec5d260e8f43053da7917cff5711da59b64b3411f94337cbdf790953b869bbf048f414ddf5e795a191def09dceecad1e3075ee427a9ce14b141a95c37bb0ef45d65c6b15451fcedfb415b37ea1e58c88ddef9ca7214251f0faf6230333cbd8a1eed21bbab4773716c5ae06c2b616539299af86ca1933b7ec59dfd5afe788c44cd0290c21aa392bae376d44fc76be12dc86e1dad04797d1a431666b49df6414b24856989f2497bbc94e1488c3176483be3c7ad30569abf04ac350348a5e21144a91027b058fde6b17d47dd4610833ba95d8984db6c56cc95b929a3cf7992743acffb245884a68a77d57e3e712e59fa4600d027917716511a755d14813f972052f152635bf8e7823485797852fa2c76079ff1a191ee9764d8a1b0b39adf3e9908327efb11c7f1ecdab539e340f8baf1f73e34429bf47a10e44cc9009df126b095836c98c438b554e62e7e5dd669b871d43fc15943f127590",
	"b9001454cf213af425c50c53eda9fb0a8f477914b996828f82c36868d8681423b50988b3b8a8f11229dac8f362423b6f9df95a562db1059b30881292dda968a9745b8f375de3e3d2f8b51cae8fd1e0f76322120716df8f4e32ee647644dd3e31f4def788b1aecfaf83cb4d4515c49cefd4502441eca67d3a66bb34c2c6199ebc59eb51d104397e383d5cd192662ea5aaafe2ed3092e4ddd065bb792d89fc433b77ac3417dcba98660d62286dbd1252b1607b312bab299c8d29b882c0c338993fb6866245d446f14322b2d86b816f9fe189abfd3aef8bf725337bdb5befd354dc62515498ca4ad6092a950fadc2f7a4cc8a98e314c7b2fb9b95930cf1c3be1ac65ee9973ba981c6566156fbf57323e3b2e0631d1987078182bb3c287c1caca93fa9cca1d2f2c80c4c753a45a4715f1ececac3d7b0afa4a3514e6206f8abeb27502c4e61accea0dd8781ffd2487c7d26ab06975e79c87562f3ab22d884d7dab2319b37db14273946997badcb35c557a4e363f135a68488314f34d519f3a025ee91e2691a9d6518d4b20ee4d57dffb42b93126aa348ca3e4ed91978b75d3834e6eb2c885651fdd90965f4c5a3eb28ac30a9a6f214e1e48ea9c03418e204c9d872d0996cee2cd16755ee91a94c217d3d85ed4fb667faf8837677af6b240cb3bbf78dff01012287a7cbdae6ce110625d065f308a3cda249b4a7b72903a1fbede8e683a3d680c44bfeaa5bbf55663da814a634d556e2377c2a4ba99c2b7a6307cde0910d0c170dc03bd7de5ba544d69a6466b98f7db0e76da872915d1e05c0f8223414fba8c391be72491955a3bd9495cf600b84dfcf017ab3999b075a932eceef5bba1b08cf47f708",
	"b900c6e9378c3f34cd19992208da794bd4429298c9269c1dc2e1cd48dc0500da1ec42ebb39531f0acf259b81c11c2c7ceb73b26d5de314bf29df1491bf410cfba581bbd2088b2ee6428cbad903acc64c3a26274dbfd8f2a578f6d16b916ce4992e7a3886f9abf4a99a9141c12484cdd7502db077994a3ed0a268efce8b9bf64dd238295e686b9c57d5ccfdf311ed76590f8fa1b9c91a556047f3a435373358a5342ffc5b3dd69ecf7b509e68bbb07d6d565233c4e7a2526c3525b6c619899215ad343ba4ced9ca6fa4ed231244108b3a2999679b6646149a4d12d201168152aa6c9b004c5c84e191e8a8eac779c348e35c058b3bdc972ad1ba10d31ba96a1c6153828f59e97bae5f5c1c80b0d0909ff615902b5e67466f00b6f65f0cc3cf43e2d468a8ad52599cfdcf4dc9acaacd124432c98ebd33bcd2e1d7785812242b59c20542b0365ec9646eecb2283787076d678f7bf0a2cde29729cd0c3d4869a669fffd72a06e96e68d89da7e725776877f30248478d1a3fd8876f62ebd0e63f3ad4a4ba38cbac82bcdb9948b9bd3ad1678d34c4d068da1785846f948e6bd0e5ea56c1444d8af5f70c75d3d217956a629a77032ce329ce688672341018ecc8d7435e97dd805f2d74ca3e812987b04ba2ddc1146f96a195631a38ad6dced1ee1e8a4f6376b06351f846b972c723f5ce72a2b930e3a39e625378a6131560ac890a03ec742d87fa96d1e8e64e1ddb62864672f81981b076da480e0def5ba608816de4a3666b131196e82b594f2e50a6e4c9c9f75527dce6f92db25558523cd3a53dae9917c2611b0cdfc725d619ca575260b1a68a693b611af7ca54d8bd47e198b5da235a2326876d487ea319b0cd08740",
};
#define NUM_KATS (sizeof GIBBS_DET512_KAT / sizeof GIBBS_DET512_KAT[0])
#endif

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

/*
 * Test the full pipeline: Gibbs keygen → det512 compressed sign →
 * det512 compressed verify → det512 CT convert → det512 CT verify.
 * Uses the workbuf API variants.
 */
static int
test_pipeline_workbuf(int trial)
{
	uint8_t pubkey[FALCON_DET512_PUBKEY_SIZE];
	uint8_t privkey[FALCON_DET512_PRIVKEY_SIZE];
	uint8_t sig_comp[FALCON_DET512_SIG_COMPRESSED_MAXSIZE];
	uint8_t sig_ct[FALCON_DET512_SIG_CT_SIZE];
	size_t sig_comp_len;
	uint8_t msg[MSG_LEN];
	uint8_t keygen_wb[FALCON_DET512_WORKBUF_KEYGEN_SIZE];
	uint8_t sign_wb[FALCON_DET512_WORKBUF_SIGN_COMPRESSED_SIZE];
	uint8_t verify_wb[FALCON_DET512_WORKBUF_VERIFY_COMPRESSED_SIZE];
	uint8_t ct_wb[FALCON_DET512_WORKBUF_CONVERT_TO_CT_SIZE];
	uint8_t verify_ct_wb[FALCON_DET512_WORKBUF_VERIFY_CT_SIZE];
	char key_seed[32], msg_seed[32];
	shake256_context key_rng;
	int r;
	unsigned oldcw;

	oldcw = set_fpu_cw(2);

	/* Deterministic message. */
	snprintf(msg_seed, sizeof msg_seed, "%s-%d", MSG_SEED, trial);
	{
		shake256_context msg_rng;
		shake256_init_prng_from_seed(&msg_rng, msg_seed, strlen(msg_seed));
		shake256_extract(&msg_rng, msg, MSG_LEN);
	}

	/* Gibbs keygen via the workbuf API. */
	snprintf(key_seed, sizeof key_seed, "%s-%d", KEY_SEED, trial);
	shake256_init_prng_from_seed(&key_rng, key_seed, strlen(key_seed));

	memset(pubkey, 0, sizeof pubkey);
	memset(privkey, 0, sizeof privkey);
	memset(keygen_wb, 0, sizeof keygen_wb);

	r = falcon_det512_keygen_with_workbuf(&key_rng, privkey, pubkey,
		keygen_wb, sizeof keygen_wb);
	if (r != 0) {
		printf("FAIL trial %d: workbuf keygen returned %d\n", trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	/* det512 compressed sign (workbuf API). */
	memset(sig_comp, 0, sizeof sig_comp);
	memset(sign_wb, 0, sizeof sign_wb);

	r = falcon_det512_sign_compressed_with_workbuf(
		sig_comp, &sig_comp_len, privkey, msg, MSG_LEN,
		sign_wb, sizeof sign_wb);
	if (r != 0) {
		printf("FAIL trial %d: workbuf sign returned %d\n", trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	/* Verify salt version byte. */
	if (falcon_det512_get_salt_version(sig_comp)
		!= FALCON_DET512_CURRENT_SALT_VERSION) {
		printf("FAIL trial %d: bad salt version\n", trial);
		set_fpu_cw(oldcw);
		return 0;
	}

	/* det512 compressed verify (workbuf API). */
	memset(verify_wb, 0, sizeof verify_wb);

	r = falcon_det512_verify_compressed_with_workbuf(
		sig_comp, sig_comp_len, pubkey, msg, MSG_LEN,
		verify_wb, sizeof verify_wb);
	if (r != 0) {
		printf("FAIL trial %d: workbuf verify_compressed returned %d\n",
			trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	/* Convert compressed → CT (workbuf API). */
	memset(sig_ct, 0, sizeof sig_ct);
	memset(ct_wb, 0, sizeof ct_wb);

	r = falcon_det512_convert_compressed_to_ct_with_workbuf(
		sig_ct, sig_comp, sig_comp_len, ct_wb, sizeof ct_wb);
	if (r != 0) {
		printf("FAIL trial %d: convert_to_ct returned %d\n", trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	/* CT verify (workbuf API). */
	memset(verify_ct_wb, 0, sizeof verify_ct_wb);

	r = falcon_det512_verify_ct_with_workbuf(
		sig_ct, pubkey, msg, MSG_LEN,
		verify_ct_wb, sizeof verify_ct_wb);
	if (r != 0) {
		printf("FAIL trial %d: workbuf verify_ct returned %d\n",
			trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

#ifdef GENERATE_KATS
	/* Print KAT: compressed signature as hex. */
	printf("\t\"");
	for (size_t i = 0; i < sig_comp_len; i++) {
		printf("%02x", sig_comp[i]);
	}
	printf("\",\n");
#endif

	set_fpu_cw(oldcw);
	return 1;
}

/*
 * Test auxiliary functions (pubkey_coeffs, hash_to_point_coeffs,
 * s2_coeffs, s1_coeffs) with Gibbs-generated keys.
 */
static int
test_aux_functions(int trial)
{
	uint8_t pubkey[FALCON_DET512_PUBKEY_SIZE];
	uint8_t privkey[FALCON_DET512_PRIVKEY_SIZE];
	uint8_t sig_comp[FALCON_DET512_SIG_COMPRESSED_MAXSIZE];
	uint8_t sig_ct[FALCON_DET512_SIG_CT_SIZE];
	size_t sig_comp_len;
	uint8_t msg[MSG_LEN];
	uint8_t keygen_wb[FALCON_DET512_WORKBUF_KEYGEN_SIZE];
	uint8_t sign_wb[FALCON_DET512_WORKBUF_SIGN_COMPRESSED_SIZE];
	uint8_t hash_work[FALCON_DET512_WORKBUF_HASH_TO_POINT_SIZE];
	uint8_t s1_work[FALCON_DET512_WORKBUF_S1COEFFS_SIZE];
	uint16_t h_coeffs[GIBBS_N];
	uint16_t c_coeffs[GIBBS_N];
	int16_t s2_coeffs[GIBBS_N];
	int16_t s1_coeffs[GIBBS_N];
	char key_seed[32], msg_seed[32];
	shake256_context key_rng;
	int r;
	unsigned oldcw;

	oldcw = set_fpu_cw(2);

	snprintf(msg_seed, sizeof msg_seed, "%s-%d", MSG_SEED, trial);
	{
		shake256_context msg_rng;
		shake256_init_prng_from_seed(&msg_rng, msg_seed, strlen(msg_seed));
		shake256_extract(&msg_rng, msg, MSG_LEN);
	}

	snprintf(key_seed, sizeof key_seed, "%s-%d", KEY_SEED, trial);
	shake256_init_prng_from_seed(&key_rng, key_seed, strlen(key_seed));

	memset(pubkey, 0, sizeof pubkey);
	memset(privkey, 0, sizeof privkey);
	memset(keygen_wb, 0, sizeof keygen_wb);

	r = falcon_det512_keygen_with_workbuf(&key_rng, privkey, pubkey,
		keygen_wb, sizeof keygen_wb);
	if (r != 0) {
		printf("FAIL aux trial %d: keygen returned %d\n", trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	/* Sign to get a valid signature. */
	memset(sig_comp, 0, sizeof sig_comp);
	memset(sign_wb, 0, sizeof sign_wb);

	r = falcon_det512_sign_compressed_with_workbuf(
		sig_comp, &sig_comp_len, privkey, msg, MSG_LEN,
		sign_wb, sizeof sign_wb);
	if (r != 0) {
		printf("FAIL aux trial %d: sign returned %d\n", trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	/* pubkey_coeffs. */
	r = falcon_det512_pubkey_coeffs(h_coeffs, pubkey);
	if (r != 0) {
		printf("FAIL aux trial %d: pubkey_coeffs returned %d\n",
			trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	/* hash_to_point_coeffs (workbuf). */
	memset(hash_work, 0, sizeof hash_work);
	r = falcon_det512_hash_to_point_coeffs_with_workbuf(
		c_coeffs, msg, MSG_LEN,
		FALCON_DET512_CURRENT_SALT_VERSION,
		hash_work, sizeof hash_work);
	if (r != 0) {
		printf("FAIL aux trial %d: hash_to_point_coeffs returned %d\n",
			trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	/* Convert sig to CT then extract s2. */
	memset(sig_ct, 0, sizeof sig_ct);
	r = falcon_det512_convert_compressed_to_ct(
		sig_ct, sig_comp, sig_comp_len);
	if (r != 0) {
		printf("FAIL aux trial %d: convert_to_ct returned %d\n",
			trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	r = falcon_det512_s2_coeffs(s2_coeffs, sig_ct);
	if (r != 0) {
		printf("FAIL aux trial %d: s2_coeffs returned %d\n", trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	/* Compute s1 = c - s2*h (workbuf API). */
	memset(s1_work, 0, sizeof s1_work);
	r = falcon_det512_s1_coeffs_with_workbuf(
		s1_coeffs, h_coeffs, c_coeffs, s2_coeffs,
		s1_work, sizeof s1_work);
	if (r != 0) {
		printf("FAIL aux trial %d: s1_coeffs returned %d\n", trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	/* Verify with the non-workbuf wrappers for coverage. */
	r = falcon_det512_verify_compressed(sig_comp, sig_comp_len,
		pubkey, msg, MSG_LEN);
	if (r != 0) {
		printf("FAIL aux trial %d: verify_compressed returned %d\n",
			trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	r = falcon_det512_verify_ct(sig_ct, pubkey, msg, MSG_LEN);
	if (r != 0) {
		printf("FAIL aux trial %d: verify_ct returned %d\n", trial, r);
		set_fpu_cw(oldcw);
		return 0;
	}

	set_fpu_cw(oldcw);
	return 1;
}

int
main(void)
{
	int failures = 0;
	int i;

	printf("Gibbs + det512 integration test (logn=%d)\n", GIBBS_LOGN);

	/* Pipeline: keygen → sign → verify, workbuf API. */
#ifdef GENERATE_KATS
	printf("\nstatic const char *const GIBBS_DET512_KAT[] = {\n");
#endif
	for (i = 0; i < TRIALS; i++) {
		if (!test_pipeline_workbuf(i)) {
			failures++;
		}
#ifndef GENERATE_KATS
		printf(".");
		fflush(stdout);
#endif
	}
#ifdef GENERATE_KATS
	printf("};\n\n");
#else
	printf("\n");
#endif

	/* Verify KAT vectors (only when not generating). */
#ifndef GENERATE_KATS
	if (NUM_KATS > 0) {
		for (i = 0; i < (int)NUM_KATS && i < TRIALS; i++) {
			uint8_t pubkey[FALCON_DET512_PUBKEY_SIZE];
			uint8_t privkey[FALCON_DET512_PRIVKEY_SIZE];
			uint8_t sig_comp[FALCON_DET512_SIG_COMPRESSED_MAXSIZE];
			size_t sig_comp_len;
			uint8_t expected[FALCON_DET512_SIG_COMPRESSED_MAXSIZE];
			uint8_t msg[MSG_LEN];
			uint8_t keygen_wb[FALCON_DET512_WORKBUF_KEYGEN_SIZE];
			uint8_t sign_wb[FALCON_DET512_WORKBUF_SIGN_COMPRESSED_SIZE];
			char key_seed[32], msg_seed[32];
			shake256_context key_rng;
			int r;
			size_t elen;

			snprintf(msg_seed, sizeof msg_seed, "%s-%d", MSG_SEED, i);
			{
				shake256_context msg_rng;
				shake256_init_prng_from_seed(&msg_rng,
					msg_seed, strlen(msg_seed));
				shake256_extract(&msg_rng, msg, MSG_LEN);
			}

			snprintf(key_seed, sizeof key_seed, "%s-%d", KEY_SEED, i);
			shake256_init_prng_from_seed(&key_rng,
				key_seed, strlen(key_seed));

			memset(pubkey, 0, sizeof pubkey);
			memset(privkey, 0, sizeof privkey);
			memset(keygen_wb, 0, sizeof keygen_wb);

			r = falcon_det512_keygen_with_workbuf(&key_rng,
				privkey, pubkey, keygen_wb, sizeof keygen_wb);
			if (r != 0) {
				printf("KAT keygen FAIL trial %d: %d\n", i, r);
				failures++;
				continue;
			}

			memset(sig_comp, 0, sizeof sig_comp);
			memset(sign_wb, 0, sizeof sign_wb);

			r = falcon_det512_sign_compressed_with_workbuf(
				sig_comp, &sig_comp_len, privkey, msg, MSG_LEN,
				sign_wb, sizeof sign_wb);
			if (r != 0) {
				printf("KAT sign FAIL trial %d: %d\n", i, r);
				failures++;
				continue;
			}

			elen = hextobin(expected, sizeof expected,
				GIBBS_DET512_KAT[i]);
			if (elen != sig_comp_len) {
				printf("KAT length FAIL trial %d: "
					"got %zu, expected %zu\n",
					i, sig_comp_len, elen);
				failures++;
				continue;
			}
			if (memcmp(sig_comp, expected, sig_comp_len) != 0) {
				printf("KAT mismatch trial %d\n", i);
				failures++;
				continue;
			}
			printf(".");
			fflush(stdout);
		}
		printf("\n");
	}
#endif

	/* Auxiliary functions (pubkey_coeffs, hash, s1, s2). */
	for (i = 0; i < TRIALS; i++) {
		if (!test_aux_functions(i)) {
			failures++;
		}
	}

	if (failures > 0) {
		printf("FAILED: %d failure(s)\n", failures);
		return 1;
	}
	printf("OK\n");
	return 0;
}
