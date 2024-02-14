#include "includes.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>

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

int sendToSocket(int sockfd, struct qfactor_client_msg * msg)
{
	/* TODO: error handling for binn_object() */
	binn * o = binn_object();
	/* TODO: error handling for binn_object_set_uint32() */
	binn_object_set_uint32(o, "msg_type", msg->msg_type);
	/* TODO: error handling for binn_object_set_uint32() */
	binn_object_set_uint32(o, "op", msg->op);

	/* TODO: error handling for binn_ptr() */
	u_char * ptr = (u_char *) binn_ptr(o);
	/* TODO: error handling for binn_size() */
	u_char * end = ptr + binn_size(o);
	/* TODO: error handling for write() */
	while (ptr < end)
		ptr += write(sockfd, ptr, end - ptr);

	/* TODO: error handling for binn_free() */
	binn_free(o);
	return 0;
}

int readFromSocket(int sockfd, char * msg, size_t len)
{
	char buf[QFACTOR_BUFSIZE_FROM_SERVER];
	size_t nread = 0;
	ssize_t newread = 0;
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
	/* TODO: handle binn_object_blob() error conditions */
	struct qfactor_server_msg * rcvd = binn_object_blob(o, "Msg", &value);
	/* TODO: handle this better */
	if (rcvd->msg_type != QFACTOR_HPNSSH_MSG) {
		return -1;
	}
	snprintf(msg, len, "%s, %d, %d, %d, %d", rcvd->timestamp, rcvd->op, rcvd->hop_latency, rcvd->queue_occupancy, rcvd->switch_id);
	return 0;
}

struct qfactor_ctx {
	int sockfd;
	int autoclose;
};

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
	/* TODO: add error checking for sendToSocket() */
	sendToSocket(qctx->sockfd, &cmsg);
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
