#include "includes.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "qfactor.h"
#include "binn.h"

#define QFACTOR_BUFSIZE_FROM_SERVER 77
#define QFACTOR_BUFSIZE_FROM_CLIENT 19

struct qfactor_client_msg {
	u_int msg_type;
	u_int op;
};

struct qfactor_server_msg {
	u_int msg_type;
	u_int op;
	u_int hop_latency;
	u_int queue_occupancy;
	u_int switch_id;
	u_char timestamp[QFACTOR_MS_CTIME_BUF_LEN];
};

struct qfactor_ctx {
	int sockfd;
	int autoclose;
};

int sendToSocket(int sockfd, struct qfactor_client_msg * msg)
{
	u_char * end = NULL;
	u_char *ptr = NULL;
	int ret = 0;

	binn * o = binn_object();
	if (o == NULL)
		goto fail;

	if (binn_object_set_uint32(o, "msg_type", msg->msg_type) == FALSE)
		goto fail;

	if (binn_object_set_uint32(o, "op", msg->op) == FALSE)
		goto fail;

	ptr = (u_char *) binn_ptr(o);
	if (ptr == NULL)
		goto fail;

	ret = binn_size(o);
	/* o should not have a size of 0 at this point */
	if (ret != 0)
		end = ptr + ret;
	else
		goto fail;

	while (ptr < end) {
		ret = write(sockfd, ptr, end - ptr);
		if (ret == -1) {
			error("Write failed with %s", strerror(errno));
			debug_f("Write failed with %s", strerror(errno));
			goto fail;
		}
		ptr += ret;
	}

	binn_free(o);
	return 0;
fail:
	binn_free(o);
	return -1;
}

int readFromSocket(int sockfd, char * msg, size_t len)
{
	char buf[QFACTOR_BUFSIZE_FROM_SERVER];
	size_t nread = 0;
	ssize_t newread = 0;
	struct qfactor_server_msg * rcvd = NULL;

	while(nread < sizeof(buf)) {
		newread = read(sockfd, buf + nread, sizeof(buf) - nread);
		if (newread < 0) { /* signal or error */
			if (errno = EINTR) { /* signals */
				continue;
			} else {/* errors */
				return -1;
			} /* TODO: more carefully consider read() error conditions */
		} else if (newread == 0) { /* EOF before message completed */
			return -1;
		} else /* read some data */
			nread += newread;
	}
	binn * o = (binn *) buf;
	int value = 0;
	/* handle binn_object_blob() error conditions, any error return FALSE aka 0*/
	rcvd = binn_object_blob(o, "Msg", &value);
	if (value == 0)
		return -1;
	/* TODO: handle this better */
	if (rcvd->msg_type != QFACTOR_HPNSSH_MSG) {
		return -1;
	}
	snprintf(msg, len, "%s, %d, %d, %d, %d", rcvd->timestamp, rcvd->op, rcvd->hop_latency, rcvd->queue_occupancy, rcvd->switch_id);
	return 0;
}

void qfactor_set_autoclose(struct qfactor_ctx * qctx) {
	if (qctx)
		qctx->autoclose = 1;
}

void qfactor_close(struct qfactor_ctx * qctx)
{
	if (qctx == NULL)
		return;
	close(qctx->sockfd);
	free(qctx);
}

struct qfactor_ctx * qfactor_open()
{
	struct qfactor_ctx * qctx = malloc(sizeof(struct qfactor_ctx));
	qctx->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	qctx->autoclose = 0;
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(5525);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (connect(qctx->sockfd, &addr, sizeof(addr)) != 0)
		return NULL;
	return qctx;
}

int qfactor_read(struct qfactor_ctx * qctx, char * smsg, size_t len)
{
	if (smsg == NULL || qctx == NULL)
		return -1;
	struct qfactor_client_msg cmsg = { QFACTOR_HPNSSH_MSG, QFACTOR_READ };
	if (sendToSocket(qctx->sockfd, &cmsg) == -1)
		return -1;
	int ret = readFromSocket(qctx->sockfd, smsg, len);
	if (qctx->autoclose)
		qfactor_close(qctx);
	return ret;
}

int qfactor_write_header(char * hdr, size_t len) {
	char static_hdr[] = "qfactor_timestamp, qfactor_operation, qfactor_hop_latency, qfactor_queue_occupancy, qfactor_switch_id";
	if (strlen(static_hdr) + 1 > len)
		return -1;
	if (hdr == NULL)
		return -1;
	strncpy(hdr, static_hdr, len);
	return 0;
}
