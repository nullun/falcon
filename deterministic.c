#include <stdint.h>
#include <string.h>

#include "falcon.h"
#include "inner.h"
#include "deterministic.h"

#define Q     12289

// Domain separator used to construct the fixed versioned salt string.
static const uint8_t det_salt_domain[38] = {"FALCON_DET"};

// Construct the fixed salt for a given version.
static void det_write_salt(uint8_t dst[40], unsigned logn, uint8_t salt_version) {
	dst[0] = salt_version;
	dst[1] = (uint8_t)logn;
	memcpy(dst+2, det_salt_domain, 38);
}

// Construct the corresponding salted signature from an unsalted one.
static void det_resalt(uint8_t *salted_sig, unsigned logn,
        const uint8_t *unsalted_sig, size_t unsalted_sig_len) {

	salted_sig[0] = unsalted_sig[0] & ~0x80; // Reset MSB to 0.
	det_write_salt(salted_sig+1, logn, unsalted_sig[1]);
	memcpy(salted_sig+41, unsalted_sig+2, unsalted_sig_len-2);
}


/* ---- Instantiate det1024 (n = 1024, logn = 10) ---- */
#define DET_LOGN                  FALCON_DET1024_LOGN
#define DET_FN(name)              falcon_det1024_##name
#define DET_PUBKEY_SIZE           FALCON_DET1024_PUBKEY_SIZE
#define DET_PRIVKEY_SIZE          FALCON_DET1024_PRIVKEY_SIZE
#define DET_CURRENT_SALT_VERSION  FALCON_DET1024_CURRENT_SALT_VERSION
#define DET_SIG_COMPRESSED_HEADER FALCON_DET1024_SIG_COMPRESSED_HEADER
#define DET_SIG_CT_HEADER         FALCON_DET1024_SIG_CT_HEADER
#define DET_SIG_CT_SIZE           FALCON_DET1024_SIG_CT_SIZE
#include "deterministic_impl.h"


/* ---- Instantiate det512 (n = 512, logn = 9) ---- */
#define DET_LOGN                  FALCON_DET512_LOGN
#define DET_FN(name)              falcon_det512_##name
#define DET_PUBKEY_SIZE           FALCON_DET512_PUBKEY_SIZE
#define DET_PRIVKEY_SIZE          FALCON_DET512_PRIVKEY_SIZE
#define DET_CURRENT_SALT_VERSION  FALCON_DET512_CURRENT_SALT_VERSION
#define DET_SIG_COMPRESSED_HEADER FALCON_DET512_SIG_COMPRESSED_HEADER
#define DET_SIG_CT_HEADER         FALCON_DET512_SIG_CT_HEADER
#define DET_SIG_CT_SIZE           FALCON_DET512_SIG_CT_SIZE
#include "deterministic_impl.h"
