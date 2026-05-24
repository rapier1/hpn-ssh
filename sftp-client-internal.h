/* sftp-client-internal.h — narrow internal API exposed by sftp-client.c
 * to HPN-only client files (sftp-client-hpn.c).
 *
 * This file is part of HPN-SSH and is NOT part of upstream OpenSSH.
 * It exists so HPN extension code can implement new SFTP wire
 * transactions (hpn-bundle-fetch, etc.) without that code accreting
 * inside sftp-client.c, which would inflate the diff against upstream
 * on every merge.
 *
 * Upstream merge note: sftp-client.c gains only:
 *   - `static` qualifier removed from send_msg / get_msg / get_handle
 *   - two trivial accessor functions at end of file
 *     (sftp_conn_alloc_msg_id, sftp_conn_has_hpn_bundle_fetch)
 * Nothing in this header is needed by upstream code paths.
 */

#ifndef _SFTP_CLIENT_INTERNAL_H
#define _SFTP_CLIENT_INTERNAL_H

#include <sys/types.h>
#include <stdarg.h>

struct sftp_conn;
struct sshbuf;

/*
 * Send an SFTP message over the connection.  Returns 0 on success,
 * -1 if conn is dead.  Marks conn dead on transport failure.
 */
int  send_msg(struct sftp_conn *conn, struct sshbuf *m);

/*
 * Receive one SFTP message into the supplied buffer.  Returns 0 on
 * success, non-zero on protocol/transport error (also marks conn dead
 * via the HPN dead flag).
 */
int  get_msg(struct sftp_conn *conn, struct sshbuf *m);

/*
 * Issue one outbound request and read back the SSH_FXP_HANDLE reply.
 * Returns a newly-malloc'd handle buffer on success (caller frees), or
 * NULL on failure.  *len is set to the handle length on success.
 *
 * `errfmt` (printf-style) is used to format the per-failure error log
 * message.  expected_id must match the reply's id field.
 */
u_char *get_handle(struct sftp_conn *conn, u_int expected_id, size_t *len,
    const char *errfmt, ...) __attribute__((format(printf, 4, 5)));

/*
 * Allocate and return the next outbound SFTP message id for this
 * connection.  Equivalent to `conn->msg_id++` but doesn't require the
 * caller to know struct sftp_conn's layout.
 */
u_int sftp_conn_alloc_msg_id(struct sftp_conn *conn);

#endif /* _SFTP_CLIENT_INTERNAL_H */
