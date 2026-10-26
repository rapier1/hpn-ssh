// cc_fuzz_target for the misc.c/match.c string & hostname parsing
// matrix: these helpers process attacker-influenced data (server-
// supplied hostnames and addresses, user-supplied patterns and time
// specs) on every connection.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" {

#include "includes.h"
#include "misc.h"
#include "match.h"
#include "xmalloc.h"

int LLVMFuzzerTestOneInput(const uint8_t *s0, size_t slen);

int LLVMFuzzerTestOneInput(const uint8_t *s0, size_t slen)
{
char tmp[4097];
char *f0, *f1, *f2;
char *o1 = NULL, *o2 = NULL, *o3 = NULL;
uint64_t t;
double d;
int port, r;
size_t l1, l2;

if (slen < 3 || slen > 4096)
return 0;

memcpy(tmp, s0, slen);
tmp[slen] = '\0';

f0 = tmp;
l1 = strlen(f0);
f1 = (l1 + 1 <= slen) ? tmp + l1 + 1 : (char *)"";
l2 = strlen(f1);
f2 = ((size_t)(f1 - tmp) + l2 + 1 <= slen) ? f1 + l2 + 1 : (char *)"";

/* match.c: patterns vs hostnames/addresses. */
(void)match_pattern(f0, f1);
(void)match_pattern_list(f0, f1, 0);
(void)match_pattern_list(f0, f1, 1);
(void)match_user(f0, f1, f2, f1);
(void)match_host_and_ip(f0, f1, f2);

/* misc.c parsers. */
(void)a2port(f0);
(void)convtime(f0);
(void)parse_absolute_time(f0, &t);
(void)parse_pattern_interval(f0, &o1, &d);
free(o1);
(void)parse_ipqos(f0);
(void)tilde_expand(f0, getuid(), &o1);
free(o1);

r = parse_user_host_path(f0, &o1, &o2, &o3);
if (r == 0) {
free(o1);
free(o2);
free(o3);
}
r = parse_user_host_port(f0, &o1, &o2, &port);
if (r == 0) {
free(o1);
free(o2);
}

o1 = put_host_port(f0, 22);
free(o1);

/* strdelim family over a fresh copy (returns point INTO the buffer;
 * nothing to free but the copy itself). */
{
char *base = xstrdup(f0);
char *cp = base;
(void)strdelim(&cp);
free(base);
base = xstrdup(f1);
cp = base;
(void)strdelimw(&cp);
free(base);
}

return 0;
}

} // extern
