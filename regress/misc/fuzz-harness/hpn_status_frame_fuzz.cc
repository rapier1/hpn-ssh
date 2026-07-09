/*
 * Fuzz the HPN status-relay frame parser (hpn-status-frame.h), the one
 * piece of the status relay that faces remote input: the launching
 * hpnscp (B) parses these frames from the -R source's stdout, which a
 * compromised source controls entirely.  The parser must never crash,
 * over-read, or loop on arbitrary bytes, and every delivered frame must
 * satisfy the header contract (validated in the callback below).
 *
 * Input layout: first byte selects the feed chunk size (1..256) so the
 * fuzzer exercises resumption across arbitrary split points, mirroring
 * short pipe reads; the rest is the byte stream.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "hpn-status-frame.h"
}

struct cb_state {
	size_t frames;
};

static void
frame_cb(u_char type, const u_char *payload, uint16_t plen, void *ctx)
{
	struct cb_state *st = (struct cb_state *)ctx;
	struct hpns_hello h;
	struct hpns_progress pr;
	struct hpns_end e;
	struct hpns_filefail ff;
	volatile uint64_t sink = 0;

	st->frames++;
	/* header contract: parser never delivers an oversized payload */
	if (plen > HPNS_MAX_PAYLOAD)
		abort();

	/* exercise the strict decoders exactly as the consumer does;
	 * touch every field so ASan sees any over-read */
	switch (type) {
	case HPNS_T_HELLO:
		if (hpns_decode_hello(payload, plen, &h) == 0)
			sink = h.proto_ver + h.caps + h.total_bytes +
			    h.total_files + h.streams;
		break;
	case HPNS_T_PROGRESS:
		if (hpns_decode_progress(payload, plen, &pr) == 0)
			sink = pr.bytes_done + pr.bytes_total + pr.rate_bps +
			    pr.eta_sec + pr.files_done + pr.files_total +
			    pr.workers_active + pr.workers_stalled + pr.flags;
		break;
	case HPNS_T_END:
		if (hpns_decode_end(payload, plen, &e) == 0)
			sink = e.bytes_done + e.files_done +
			    e.files_failed + e.ok;
		break;
	case HPNS_T_FILEFAIL:
		if (hpns_decode_filefail(payload, plen, &ff) == 0) {
			/* read every declared path byte so ASan catches an
			 * over-read if the decoder ever trusts a bad length */
			for (uint16_t i = 0; i < ff.path_len; i++)
				sink += ff.path[i];
			sink += ff.kind + ff.path_len;
		}
		break;
	default:
		/* unknown type: consumer skips it */
		break;
	}
	(void)sink;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct hpns_parser ps;
	struct cb_state st;
	size_t chunk, n, unconsumed;

	if (size < 1)
		return 0;
	chunk = (size_t)(data[0] % 255) + 1;
	data++;
	size--;

	memset(&ps, 0, sizeof(ps));
	memset(&st, 0, sizeof(st));

	while (size > 0) {
		n = size < chunk ? size : chunk;
		if (hpns_parser_feed(&ps, data, n, frame_cb, &st,
		    &unconsumed) != 0) {
			/* failure latches: a second feed must also fail */
			if (unconsumed > n)
				abort();
			if (hpns_parser_feed(&ps, data, n, frame_cb, &st,
			    NULL) == 0)
				abort();
			break;
		}
		if (unconsumed != 0)
			abort();	/* success must consume everything */
		data += n;
		size -= n;
	}
	return 0;
}
