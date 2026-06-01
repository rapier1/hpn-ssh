/*
 * Unit tests for the TCP_INFO health monitor: tcpi-portable.{c,h} and
 * sftp-hpn-congestion.{c,h}.  Self-contained driver with its own main()
 * (no test_helper), exits 0 on success, nonzero on first failure.
 *
 * On platforms without a usable TCP_INFO the live-path tests are skipped
 * and only the UNSUPPORTED contract is checked, so the suite passes
 * everywhere tcpi_portable_supported() is honest.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tcpi-portable.h"
#include "sftp-hpn-congestion.h"

#define FAIL(fmt, ...) do {					\
	fprintf(stderr, "FAIL %s:%d: " fmt "\n",		\
	    __func__, __LINE__, ##__VA_ARGS__);			\
	exit(1);						\
} while (0)

#define OK(name) printf("ok  %s\n", name)

/* Bring up an established loopback TCP connection; return the two ends. */
static void
loopback_pair(int *cli_out, int *acc_out)
{
	int ln, cli, acc;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);

	if ((ln = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		FAIL("listener socket: %s", strerror(errno));
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = 0;
	if (bind(ln, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		FAIL("bind: %s", strerror(errno));
	if (listen(ln, 1) == -1)
		FAIL("listen: %s", strerror(errno));
	if (getsockname(ln, (struct sockaddr *)&sin, &slen) == -1)
		FAIL("getsockname: %s", strerror(errno));

	if ((cli = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		FAIL("client socket: %s", strerror(errno));
	if (connect(cli, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		FAIL("connect: %s", strerror(errno));
	if ((acc = accept(ln, NULL, NULL)) == -1)
		FAIL("accept: %s", strerror(errno));

	close(ln);
	*cli_out = cli;
	*acc_out = acc;
}

/* Sample availability must always mirror ctx availability. */
static void
check_mirror(const struct sftp_hpn_tcp_health_ctx *ctx,
    const struct sftp_hpn_tcp_health *h)
{
	if (h->availability != ctx->avail)
		FAIL("availability mirror: out=%d ctx=%d",
		    h->availability, ctx->avail);
}

/* EXTENDED iff Tier-2 flags present; BASIC implies none. */
static void
check_tier_flags(const struct sftp_hpn_tcp_health *h)
{
	int t2 = (h->raw.avail_flags &
	    (TCPI_AVAIL_MIN_RTT | TCPI_AVAIL_DELIVERY_RATE)) != 0;

	if (h->availability == TCP_HEALTH_EXTENDED && !t2)
		FAIL("EXTENDED without Tier-2 flags (0x%x)",
		    h->raw.avail_flags);
	if (h->availability == TCP_HEALTH_BASIC && t2)
		FAIL("BASIC with Tier-2 flags (0x%x)", h->raw.avail_flags);
}

/* An established connection classifies live (BASIC/EXTENDED) on init. */
static void
test_live_connection(void)
{
	struct sftp_hpn_tcp_health_ctx ctx;
	struct sftp_hpn_tcp_health h;
	int cli, acc;

	if (!tcpi_portable_supported()) {
		OK("live_connection (skipped: no TCP_INFO)");
		return;
	}

	loopback_pair(&cli, &acc);
	sftp_hpn_tcp_health_ctx_init(&ctx, cli);

	if (ctx.avail != TCP_HEALTH_BASIC && ctx.avail != TCP_HEALTH_EXTENDED)
		FAIL("eager probe did not classify live: avail=%d", ctx.avail);

	if (sftp_hpn_tcp_health_poll(&ctx, &h) != 0)
		FAIL("poll returned -1 on a live connection");
	check_mirror(&ctx, &h);
	check_tier_flags(&h);

	if (h.raw.snd_mss == 0)
		FAIL("live sample has zero snd_mss");
	if ((h.raw.avail_flags & TCPI_AVAIL_TOTAL_RETRANS) &&
	    h.availability < TCP_HEALTH_BASIC)
		FAIL("retrans flagged but not classified live");

	close(cli);
	close(acc);
	OK("live_connection");
}

/* A socket where getsockopt(TCP_INFO) cannot succeed (UDP) settles to
 * UNSUPPORTED, and UNSUPPORTED is terminal (poll keeps returning -1, no
 * further reclassification). */
static void
test_non_tcp_settles(void)
{
	struct sftp_hpn_tcp_health_ctx ctx;
	struct sftp_hpn_tcp_health h;
	int fd, i, settled = 0;

	if (!tcpi_portable_supported()) {
		OK("non_tcp_settles (skipped: no TCP_INFO)");
		return;
	}

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		FAIL("socket: %s", strerror(errno));

	sftp_hpn_tcp_health_ctx_init(&ctx, fd);
	for (i = 0; i < 32; i++) {
		int r = sftp_hpn_tcp_health_poll(&ctx, &h);
		check_mirror(&ctx, &h);
		if (ctx.avail == TCP_HEALTH_UNSUPPORTED) {
			if (r != -1)	/* poll must report -1 here */
				FAIL("UNSUPPORTED but poll returned %d", r);
			settled = 1;
			break;
		}
		if (ctx.avail != TCP_HEALTH_PENDING)
			FAIL("unexpected avail %d before settling", ctx.avail);
	}
	if (!settled)
		FAIL("never settled to UNSUPPORTED in 32 polls");

	/* terminal: one more poll stays UNSUPPORTED / -1, struct zeroed */
	if (sftp_hpn_tcp_health_poll(&ctx, &h) != -1)
		FAIL("UNSUPPORTED not terminal");
	if (h.availability != TCP_HEALTH_UNSUPPORTED || h.raw.snd_mss != 0)
		FAIL("UNSUPPORTED poll did not zero output");

	close(fd);
	OK("non_tcp_settles");
}

/* On an unsupported build, init goes straight to UNSUPPORTED. */
static void
test_unsupported_contract(void)
{
	struct sftp_hpn_tcp_health_ctx ctx;
	struct sftp_hpn_tcp_health h;
	int fd;

	if (tcpi_portable_supported()) {
		OK("unsupported_contract (skipped: TCP_INFO present)");
		return;
	}

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		FAIL("socket: %s", strerror(errno));
	sftp_hpn_tcp_health_ctx_init(&ctx, fd);
	if (ctx.avail != TCP_HEALTH_UNSUPPORTED)
		FAIL("unsupported build did not init UNSUPPORTED: %d",
		    ctx.avail);
	if (sftp_hpn_tcp_health_poll(&ctx, &h) != -1)
		FAIL("unsupported poll did not return -1");
	close(fd);
	OK("unsupported_contract");
}

/* ---- wedge classifier tests (synthetic samples, no live socket) ---- */

/* A healthy EXTENDED baseline: WAN RTT, data queued, delivering fast. */
static struct sftp_hpn_tcp_health
mk_ext_sample(void)
{
	struct sftp_hpn_tcp_health h;

	memset(&h, 0, sizeof(h));
	h.availability = TCP_HEALTH_EXTENDED;
	h.raw.avail_flags = TCPI_AVAIL_MIN_RTT | TCPI_AVAIL_DELIVERY_RATE |
	    TCPI_AVAIL_TOTAL_RETRANS | TCPI_AVAIL_RWND_LIMITED |
	    TCPI_AVAIL_TOTAL_RTO;
	h.raw.snd_mss = 1460;
	h.raw.snd_cwnd = 100;			/* healthy window */
	h.raw.min_rtt = 20000;			/* 20 ms -> WAN */
	h.raw.rtt = 21000;
	h.raw.notsent_bytes = 65536;		/* we have data to send */
	h.raw.delivery_rate = 100000000;	/* ~100 MB/s, healthy */
	h.raw.delivery_rate_app_limited = 0;
	return h;
}

/* Feed up to `n` samples (mutated by `tweak`) and return the first
 * non-NONE verdict, or NONE if none fired. */
static enum sftp_hpn_wedge_verdict
drive(struct sftp_hpn_tcp_health_ctx *ctx, int n,
    void (*tweak)(struct sftp_hpn_tcp_health *, int))
{
	enum sftp_hpn_wedge_verdict v = SFTP_HPN_WEDGE_NONE;
	struct sftp_hpn_tcp_health h;
	int i;

	for (i = 0; i < n && v == SFTP_HPN_WEDGE_NONE; i++) {
		h = mk_ext_sample();
		tweak(&h, i);
		v = sftp_hpn_classify(ctx, &h);
	}
	return v;
}

static void tw_healthy(struct sftp_hpn_tcp_health *h, int i) { (void)h; (void)i; }

static void
tw_wedge(struct sftp_hpn_tcp_health *h, int i)
{
	h->raw.delivery_rate = 0;			/* stalled */
	h->raw.total_rto_time = (u_int32_t)(100 + i * 50); /* RTO accruing */
}

/* Idle but healthy: data queued, zero throughput, but NO network distress
 * (cwnd healthy, no RTO growth) -- e.g. the worker paused to hash during
 * verification.  delivery_rate=0 must NOT by itself look like a wedge. */
static void
tw_idle(struct sftp_hpn_tcp_health *h, int i)
{
	(void)i;
	h->raw.delivery_rate = 0;
}

/* Wedge on a < 6.7 kernel: no RTO accounting, cwnd collapsed, retransmits
 * climbing -> fallback path should fire. */
static void
tw_wedge_fallback(struct sftp_hpn_tcp_health *h, int i)
{
	h->raw.avail_flags &= ~TCPI_AVAIL_TOTAL_RTO;	/* simulate < 6.7 */
	h->raw.snd_cwnd = 2;				/* collapsed */
	h->raw.total_retrans = (u_int64_t)(10 + i * 3);	/* active loss */
}

/* Slow link on a < 6.7 kernel: small cwnd but NOT losing packets.  The
 * fallback's retransmit corroboration must keep this from firing. */
static void
tw_slow_link(struct sftp_hpn_tcp_health *h, int i)
{
	(void)i;
	h->raw.avail_flags &= ~TCPI_AVAIL_TOTAL_RTO;
	h->raw.snd_cwnd = 2;				/* small but stable */
	/* total_retrans stays 0 -> no loss observed */
}

static void
tw_lan(struct sftp_hpn_tcp_health *h, int i)
{
	h->raw.delivery_rate = 0;
	h->raw.total_rto_time = (u_int32_t)(100 + i * 50);
	h->raw.min_rtt = 1000;				/* 1 ms -> LAN, skip */
}

static void
tw_peer_stall(struct sftp_hpn_tcp_health *h, int i)
{
	h->raw.rwnd_limited = (u_int64_t)(1000 + i * 1000); /* peer window pinning */
	/* cwnd stays healthy (100) -> distinguishes from wedge */
}

static void
tw_path_degraded(struct sftp_hpn_tcp_health *h, int i)
{
	h->raw.total_retrans = (u_int64_t)(10 + i * 5);	/* steady loss */
	/* delivery stays healthy -> not stalled, not a wedge */
}

static void
tw_download(struct sftp_hpn_tcp_health *h, int i)
{
	h->raw.notsent_bytes = 0;			/* not sending -> receiver */
	h->raw.delivery_rate = 0;
	h->raw.total_rto_time = (u_int32_t)(100 + i * 50);
}

static void
test_classify(void)
{
	struct sftp_hpn_tcp_health_ctx ctx;
	struct sftp_hpn_tcp_health h;
	enum sftp_hpn_wedge_verdict v;
	int i;

	memset(&ctx, 0, sizeof(ctx));
	if (drive(&ctx, 30, tw_healthy) != SFTP_HPN_WEDGE_NONE)
		FAIL("healthy sample sequence produced a verdict");

	memset(&ctx, 0, sizeof(ctx));
	if (drive(&ctx, 20, tw_wedge) != SFTP_HPN_WEDGE_TCP_WEDGE)
		FAIL("sustained wedge did not classify as WEDGE");

	memset(&ctx, 0, sizeof(ctx));
	if (drive(&ctx, 20, tw_idle) != SFTP_HPN_WEDGE_NONE)
		FAIL("idle-but-healthy (zero throughput, no distress) fired");

	memset(&ctx, 0, sizeof(ctx));
	if (drive(&ctx, 20, tw_wedge_fallback) != SFTP_HPN_WEDGE_TCP_WEDGE)
		FAIL("< 6.7 fallback wedge did not classify as WEDGE");

	memset(&ctx, 0, sizeof(ctx));
	if (drive(&ctx, 30, tw_slow_link) != SFTP_HPN_WEDGE_NONE)
		FAIL("slow link (small cwnd, no loss) misclassified as wedge");

	memset(&ctx, 0, sizeof(ctx));
	if (drive(&ctx, 20, tw_lan) != SFTP_HPN_WEDGE_NONE)
		FAIL("LAN path was not skipped");

	memset(&ctx, 0, sizeof(ctx));
	if (drive(&ctx, 20, tw_peer_stall) != SFTP_HPN_WEDGE_PEER_STALL)
		FAIL("sustained rwnd-limit did not classify as PEER_STALL");

	memset(&ctx, 0, sizeof(ctx));
	if (drive(&ctx, 20, tw_path_degraded) != SFTP_HPN_WEDGE_PATH_DEGRADED)
		FAIL("sustained loss did not classify as PATH_DEGRADED");

	memset(&ctx, 0, sizeof(ctx));
	if (drive(&ctx, 20, tw_download) != SFTP_HPN_WEDGE_NONE)
		FAIL("download (notsent=0) produced a sender-side verdict");

	/* BASIC tier never acts. */
	memset(&ctx, 0, sizeof(ctx));
	for (i = 0, v = SFTP_HPN_WEDGE_NONE;
	    i < 20 && v == SFTP_HPN_WEDGE_NONE; i++) {
		h = mk_ext_sample();
		h.availability = TCP_HEALTH_BASIC;
		tw_wedge(&h, i);
		v = sftp_hpn_classify(&ctx, &h);
	}
	if (v != SFTP_HPN_WEDGE_NONE)
		FAIL("BASIC tier produced a verdict");

	/* A wedge that recovers before the sustain window must not fire. */
	memset(&ctx, 0, sizeof(ctx));
	for (i = 0; i < 5; i++) {
		h = mk_ext_sample();
		tw_wedge(&h, i);
		if (sftp_hpn_classify(&ctx, &h) != SFTP_HPN_WEDGE_NONE)
			FAIL("wedge fired before sustain window");
	}
	for (i = 0; i < 5; i++) {
		h = mk_ext_sample();		/* healthy -> resets counter */
		if (sftp_hpn_classify(&ctx, &h) != SFTP_HPN_WEDGE_NONE)
			FAIL("recovery produced a verdict");
	}
	OK("classify");
}

int
main(void)
{
	test_live_connection();
	test_non_tcp_settles();
	test_unsupported_contract();
	test_classify();
	printf("PASS tcp_health\n");
	return 0;
}
