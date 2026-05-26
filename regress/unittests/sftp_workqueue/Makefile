# HPN-SSH parallel-streams workqueue unit tests
# Self-contained: does not link against test_helper because the test
# driver provides its own main().

PROG=test_sftp_workqueue
SRCS=tests.c sftp-workqueue.c

LDADD+=-lpthread
DPADD+=

REGRESS_TARGETS=run-regress-${PROG}

run-regress-${PROG}: ${PROG}
	env ${TEST_ENV} ./${PROG} ${UNITTEST_ARGS}

.include <bsd.regress.mk>
