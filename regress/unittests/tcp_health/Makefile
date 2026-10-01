# TCP_INFO health-monitor unit tests (tcpi-portable + hpn-congestion-monitor).
# Self-contained: the driver provides its own main() and does not link
# against test_helper.

PROG=test_tcp_health
SRCS=tests.c hpn-congestion-monitor.c tcpi-portable.c

REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG} ${UNITTEST_ARGS}

.include <bsd.regress.mk>
