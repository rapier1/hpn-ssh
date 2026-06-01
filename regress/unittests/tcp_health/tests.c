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

int
main(void)
{
	test_live_connection();
	test_non_tcp_settles();
	test_unsupported_contract();
	printf("PASS tcp_health\n");
	return 0;
}
