// Fuzz the SSH KRL (Key Revocation List) binary format parser.
//
// KRL files are read by sshd (RevokedKeys) and ssh-keygen -k; a hostile
// or corrupted KRL file must never corrupt the reader. The harness parses
// the fuzz input as a KRL blob and then looks up both a plain public key
// and a certificate in the resulting revocation lists.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

#include "includes.h"
#include "sshkey.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "krl.h"
#include "log.h"
#include "fixed-keys.h"

int LLVMFuzzerTestOneInput(const uint8_t* d, size_t dlen)
{
  struct sshbuf *buf = sshbuf_from(d, dlen);
  struct ssh_krl *krl = NULL;
  struct sshkey *k = NULL;
  struct sshbuf *kb;
  int r;

  log_init("krl_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_USER, 1);

  if (ssh_krl_from_blob(buf, &krl) == 0 && krl != NULL) {
    /* Look up a fixed plain public key. */
    kb = sshbuf_from(PUB_ED25519, sizeof(PUB_ED25519) - 1);
    if (sshkey_fromb(kb, &k) == 0 && k != NULL) {
      ssh_krl_check_key(krl, k);
      sshkey_free(k);
      k = NULL;
    }
    sshbuf_free(kb);

    /* Look up a fixed certificate (exercises serial/CA sections). */
    kb = sshbuf_from(CERT_ED25519, sizeof(CERT_ED25519) - 1);
    if (sshkey_fromb(kb, &k) == 0 && k != NULL) {
      ssh_krl_check_key(krl, k);
      sshkey_free(k);
    }
    sshbuf_free(kb);
  }
  ssh_krl_free(krl); /* handles NULL */
  sshbuf_free(buf);
  return 0;
}

} // extern
