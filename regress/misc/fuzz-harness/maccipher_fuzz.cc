// cc_fuzz_target for the packet MAC/AEAD primitives: umac (umac.c) and
// the ChaCha20-Poly1305 AEAD (cipher-chachapoly-libcrypto-mt.c) verify
// and process every incoming packet, so their inputs on the wire are
// fully attacker-controlled.
//
// Input layout: [32 key][4 seq BE][2 aadlen BE][payload...].

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

#include "includes.h"
#include "umac.h"
#include "cipher-chachapoly.h"

int LLVMFuzzerTestOneInput(const uint8_t *s0, size_t slen);

int LLVMFuzzerTestOneInput(const uint8_t *s0, size_t slen)
{
uint8_t key[32];
uint32_t seq;
uint32_t aadlen;
size_t plen;
uint8_t *buf, *out;
struct umac_ctx *uc = NULL;
struct chachapoly_ctx *cc = NULL;
u_char tag[32];
u_char nonce[8] = {0};
u_int32_t plen_out;
int r;

if (slen < 38 || slen > 4096)
return 0;

memcpy(key, s0, 32);
seq = (s0[32] << 24) | (s0[33] << 16) | (s0[34] << 8) | s0[35];
aadlen = (s0[36] << 8) | s0[37];
plen = slen - 38;
if (aadlen > plen)
aadlen = plen;

/* umac: key derive, stream through, tag twice (nonce fixed). */
uc = umac_new(key);
if (uc != NULL) {
umac_update(uc, s0 + 38, plen);
umac_final(uc, tag, nonce);
umac_delete(uc);
}

/* chachapoly: encrypt then decrypt round-trip + length decode. */
cc = chachapoly_new(key, 32);
if (cc != NULL) {
buf = (uint8_t *)malloc(plen + 32);
out = (uint8_t *)malloc(plen + 32);
if (buf != NULL && out != NULL) {
memcpy(buf, s0 + 38, plen);
r = chachapoly_crypt(cc, seq, out, buf, plen - aadlen,
    aadlen, 16, 1);
if (r == 0)
(void)chachapoly_crypt(cc, seq, buf, out,
    plen - aadlen, aadlen, 16, 0);
}
free(buf);
free(out);
if (plen >= 4)
(void)chachapoly_get_length(cc, &plen_out, seq,
    s0 + 38, 4);
chachapoly_free(cc);
}

return 0;
}

} // extern
