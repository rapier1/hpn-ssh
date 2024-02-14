#ifndef QFACTOR_H
#define QFACTOR_H

#define QFACTOR_CTIME_BUF_LEN	 27
#define QFACTOR_MS_CTIME_BUF_LEN 48

/* msg_types */
#define QFACTOR_NULL_MSG	  0
#define QFACTOR_HPNSSH_MSG	  2

/* ops */
#define QFACTOR_READ		 33
#define QFACTOR_READALL		 44
#define QFACTOR_SHUTDOWN	 55
#define QFACTOR_START		 99
#define QFACTOR_READ_FS		133
#define QFACTOR_READALL_FS	144

struct qfactor_ctx;

int qfactor_read(struct qfactor_ctx * qctx, char * msg, size_t len);
struct qfactor_ctx * qfactor_open();
void qfactor_close(struct qfactor_ctx * qctx);
void qfactor_set_autoclose(struct qfactor_ctx * qctx);
int qfactor_write_header(char * hdr, size_t len);

#endif /* QFACTOR_H */
