/*
 * Copyright (c) 2025 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *  Author: Kim Mihn Kaplan (kaplan at kim-mihn.com)
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the MIT License for more details.
 *
 * You should have received a copy of the MIT License along with this library;
 * if not, see http://opensource.org/licenses/MIT.
 *
 */
/* This is an implementation of RFC 8305 based on a patch
 * supplied by Kim Minh Kaplan (kaplan at kim-minh.com).
 * Information about RFC 8305 can be found at
 * https://www.rfc-editor.org/rfc/rfc8305
 * This version *does not* provide support for
 * Section 3 where asychronous polling of DNS servers
 * is a SHOULD.
 * Section 4 requires sorting of DNS results as per
 * RFC 6724. This is provided by the getaddrinfo call
 * from gcc. This may not be available via musl.
 * Interleaving of addresses is not currently supported.
 * Section 5 is implemented.
 * Section 6 is not implemented outside of getaddrinfo
 * Section 7 in under consideration
 */


/* NOTE: There are a lot of debug statements in here
 * because we are still treating this as somewhat
 * experimental. A future version will promote this
 * to stable and we'll remove a lot of the level 2
 * debug statements then.
 */

#include "includes.h"
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <stdlib.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include "happyeyeballs.h"
#include "sshconnect.h"
#include "ssh.h"
#include "misc.h"
#include "log.h"
#include "readconf.h"

/* this is from sshconnect.c */
extern int ssh_create_socket(struct addrinfo *ai);

/* get the options struct if for the delay time */
extern Options options;

/* have we timed out? */
static int
timeout(struct timeval *tv, int timeout_ms)
 {
	if (timeout_ms <= 0)
		return 0;
	ms_subtract_diff(tv, &timeout_ms);
	return timeout_ms <= 0;
}

/* used to provide debug message in sshconnect */
char global_ntop[NI_MAXHOST];

/* used to provide information for debug statements */
char *return_fam(int fam) {
	if (fam == 10)
		return "IPv6";
	else
		return "IPv4";
}

/*
 * Return 0 if the addrinfo was not tried. Return -1 if using it
 * failed. Return 1 if it was used.
 */
static int
happy_eyeballs_initiate(const char *host, struct addrinfo *ai,
				    int *timeout_ms,
				    struct timeval *initiate,
				    int *nfds, fd_set *fds,
				    struct addrinfo *fd_ai[])
{
	int oerrno, sock;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];

	debug2_f ("Happy eyeballs initiating");
	memset(ntop, 0, sizeof(ntop));
	memset(strport, 0, sizeof(strport));
	/* If *nfds != 0 then *initiate is initialised. */
	if (*nfds &&
	    (ai == NULL ||
	     !timeout(initiate, options.happy_delay))) {
		/* Do not initiate new connections yet */
		debug2_f ("Waiting to initiate new connection");
		return 0;
	}
	/* trying to use a family we don't support */
	if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
		debug2_f ("Address family not supported");
		errno = EAFNOSUPPORT;
		return -1;
	}

	debug2_f ("Running getnameinfo for %s and %d", host, ai->ai_family);
	if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
			ntop, sizeof(ntop),
			strport, sizeof(strport),
			NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
		oerrno = errno;
		error("%s: getnameinfo failed", __func__);
		errno = oerrno;
		return -1;
	}
	memcpy(global_ntop,ntop,sizeof(ntop));
	debug2_f("RFC 8305 connecting to %.200s [%.100s] port %s.",
	      host, ntop, strport);
	debug2_f("RFC 8305: %.200s", global_ntop);
	/* Create a socket for connecting */
	sock = ssh_create_socket(ai);
	if (sock < 0) {
		/* Any error is already output */
		errno = 0;
		return -1;
	}
	if (sock >= FD_SETSIZE) {
		error("socket number to big for select: %d", sock);
		close(sock);
		return -1;
	}
	fd_ai[sock] = ai;
	/* using nonblocking sockets with select allows
	 * us to fire off new sockets without waiting for a
	 * connection to be established. This lets us avoid
	 * the use of threads. set_nonblock is in misc.c
	 * and uses fnctl */
	set_nonblock(sock);
	debug2_f("RFC 8305 pre-connect for %s", return_fam(ai->ai_family));
	if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0 &&
	    errno != EINPROGRESS) {
		error("connect to address %s port %s: %s",
		      ntop, strport, strerror(errno));
		errno = 0;
		close(sock);
		return -1;
	}
	debug_f("RFC 8305 post connect for %s", return_fam(ai->ai_family));
	monotime_tv(initiate);
	FD_SET(sock, fds);
	*nfds = MAXIMUM(*nfds, sock + 1);
	return 1;
}

static int
happy_eyeballs_process(int *nfds, fd_set *fds,
				   struct addrinfo *fd_ai[],
				   int ready, fd_set *wfds)
{
	socklen_t optlen;
	int sock, optval = 0;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];

	debug2_f("Processing RFC 8305 connections");
	for (sock = *nfds - 1; ready > 0 && sock >= 0; sock--) {
		debug2_f("RFC 8305: Processing for %s: %d", return_fam(fd_ai[sock]->ai_family), sock);
		if (FD_ISSET(sock, wfds)) {
			debug2_f("RFC 8305: FD_ISSET true for %d", sock);
			ready--;
			optlen = sizeof(optval);
			debug_f("RFC 8305: optval is %d for %d", optval, sock);
			if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
				       &optval, &optlen) < 0) {
				optval = errno;
				error("getsockopt failed: %s",
				      strerror(errno));
			} else if (optval != 0) {
				debug_f("RFC 8305: Copying data for %d on %s", optval, return_fam(fd_ai[sock]->ai_family));
				memset(ntop, 0, sizeof(ntop));
				memset(strport, 0, sizeof(strport));
				if (getnameinfo(fd_ai[sock]->ai_addr,
						fd_ai[sock]->ai_addrlen,
						ntop, sizeof(ntop),
						strport, sizeof(strport),
						NI_NUMERICHOST|NI_NUMERICSERV) != 0)
					error("connect finally failed: %s",
					      strerror(optval));
				else
					error("connect to address %s port %s finally: %s",
					      ntop, strport, strerror(optval));
			}
			FD_CLR(sock, fds);
			while (*nfds > 0 && ! FD_ISSET(*nfds - 1, fds))
				--*nfds;
			if (optval == 0) {
				debug_f("RFC 8305: unsetting nonblock for %s on %d",
				    return_fam(fd_ai[sock]->ai_family), sock);
				unset_nonblock(sock);
				return sock;
			}
			close(sock);
			errno = optval;
		}
	}
	return -1;
}

int
happy_eyeballs(const char * host, struct addrinfo *ai,
			   struct sockaddr_storage *hostaddr, int *timeout_ms)
{
	struct addrinfo *fd_ai[FD_SETSIZE]; /* 1024 */
	struct timeval initiate_tv, start_tv, select_tv, *tv;
	fd_set fds, wfds;
	int res, oerrno, diff, diff0, nfds = 0, sock = -1;

	debug_f("Starting RFC 8305/Happy Eyeballs connection");

	FD_ZERO(&fds);
	if (*timeout_ms > 0) /* default value of no timeout - use TCP default instead */
		monotime_tv(&start_tv); /* monotime_tv is in misc.c */

	/* run through potentials unless we have timed out */
	/* timeout_ms being the user defined connection timeout if
	 * they aren't using the tcp timeout */
	while ((ai != NULL || nfds > 0) &&
	       ! timeout(&start_tv, *timeout_ms)) {
		/* set up the sockets */
		res = happy_eyeballs_initiate(host, ai,
		     timeout_ms, &initiate_tv, &nfds, &fds, fd_ai);
		if (res != 0)
			ai = ai->ai_next;
		if (res == -1)
			continue;
		tv = NULL;

		/* this is just to determine the pause between
		 * calls to select. */
  		if (ai != NULL || *timeout_ms > 0) {
			debug2_f ("RFC 8305: In pause...");
			tv = &select_tv;
			if (ai != NULL) {
				diff = options.happy_delay;
				ms_subtract_diff(&initiate_tv, &diff);
				if (*timeout_ms > 0) {
					diff0 = *timeout_ms;
					ms_subtract_diff(&start_tv, &diff0);
					diff = MINIMUM(diff, diff0);
				}
			} else {
				diff = *timeout_ms;
				ms_subtract_diff(&start_tv, &diff);
			}
			tv->tv_sec = diff / 1000;
			tv->tv_usec = (diff % 1000) * 1000;
		}

		/* create a writeable set of file descriptors */
		wfds = fds;
		/* select will pause for time tv determined by the above
		 * timing caculations */
		debug2_f("RFC 8305: Starting select");
		res = select(nfds, NULL, &wfds, NULL, tv);
		debug2_f("RFC 8305: Leaving select");

		/* preserve any errors */
		oerrno = errno;
		if (res < 0) {
			error("select failed: %s", strerror(errno));
			errno = oerrno;
			continue;
		}
		/* start processing the sockets */
		debug2_f ("RFC 8305: Processing happy eyeballs fds");
		sock = happy_eyeballs_process(&nfds, &fds, fd_ai,
							  res, &wfds);
		if (sock >= 0) {
			debug_f ("RFC 8305 / Happy Eyeballs connected");
			/* we have a connection */
			memcpy(hostaddr, fd_ai[sock]->ai_addr,
			       fd_ai[sock]->ai_addrlen);
			break;
		}
		debug_f("RFC 8305: Restarting while loop.");
	}
	oerrno = errno;
	/* close other connection attempts/sockets */
	debug2_f("RFC 8305: NFDS is %d", nfds);
	while (nfds-- > 0) {
		debug2_f("RFC 8305: Running FD_ISSET on %d", nfds);
		if (FD_ISSET(nfds, &fds))
			close(nfds);
	}
	/* we timed out with no valid connections */
	if (timeout(&start_tv, *timeout_ms))
		errno = ETIMEDOUT;
	else
		errno = oerrno;
	return sock;
}
