/* $OpenBSD: sftp-glob.c,v 1.33 2023/09/10 23:12:32 djm Exp $ */
/*
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "log.h"	/* HPN: fatal, for uthash_fatal */
#include "sftp.h"
#include "sftp-common.h"
#include "sftp-client.h"
/* HPN: report a failed uthash allocation the way xmalloc does, not with
 * a silent exit. */
#define uthash_fatal(msg)	fatal("%s", msg)
#include "uthash.h"	/* HPN: the glob attribute cache */

int sftp_glob(struct sftp_conn *, const char *, int,
    int (*)(const char *, int), glob_t *);
void sftp_glob_match_attrib(struct sftp_conn *, const char *, Attrib *);
off_t sftp_glob_files_total(const glob_t *, int *);

struct SFTP_OPENDIR {
	SFTP_DIRENT **dir;
	int offset;
};

static struct {
	struct sftp_conn *conn;
} cur;

/* HPN: attributes fetched by fudge_lstat and fudge_stat during glob(3)
 * expansion, keyed by path. process_get in sftp.c reads them back, so a
 * glob match costs no second stat round trip. sftp_glob clears the cache
 * at the start of each call. */
struct glob_attrib_entry {
	char	       *path;		/* hash key (xstrdup'd) */
	Attrib		attrib;
	UT_hash_handle	hh;
};

/* HPN: the most paths the cache holds, to bound memory on a huge glob. A
 * path past the cap is not cached, and process_get stats it itself. An
 * entry is about 200 bytes with its path and hash overhead, so the cap is
 * about 50 MB. */
#define GLOB_ATTRIB_CACHE_MAX	262144
static struct glob_attrib_entry *attrib_cache;
static int attrib_cache_count;

/* HPN: empty the cache. sftp_glob calls it before each expansion. */
static void
attrib_cache_clear(void)
{
	struct glob_attrib_entry *e, *tmp;

	HASH_ITER(hh, attrib_cache, e, tmp) {
		HASH_DEL(attrib_cache, e);
		free(e->path);
		free(e);
	}
	attrib_cache_count = 0;
}

/* HPN: record a's attributes for path, replacing any earlier entry. A new
 * path is dropped once the cache holds GLOB_ATTRIB_CACHE_MAX entries. */
static void
attrib_cache_record(const char *path, const Attrib *a)
{
	struct glob_attrib_entry *e;

	/* Replace before the cap check, so glob's stat of a symlink still
	 * replaces its lstat attributes once the cache is full. */
	HASH_FIND_STR(attrib_cache, path, e);
	if (e != NULL) {
		e->attrib = *a;
		return;
	}
	if (attrib_cache_count >= GLOB_ATTRIB_CACHE_MAX)
		return;
	e = xcalloc(1, sizeof(*e));
	e->path = xstrdup(path);
	e->attrib = *a;
	HASH_ADD_KEYPTR(hh, attrib_cache, e->path, strlen(e->path), e);
	attrib_cache_count++;
}

/* HPN: copy the attributes the last sftp_glob fetched for path into out.
 * Returns 0, or -1 if path is not cached. */
static int
sftp_glob_get_attrib(const char *path, Attrib *out)
{
	struct glob_attrib_entry *e;

	HASH_FIND_STR(attrib_cache, path, e);
	if (e == NULL)
		return -1;
	*out = e->attrib;
	return 0;
}

/* HPN: the attributes of remote glob match path. sftp_glob cached them
 * when it matched, so this usually costs no round trip. A path past the
 * cache's cap falls back to a stat, so a single-file download still has
 * a known size. If that fails too, *a is left cleared. */
void
sftp_glob_match_attrib(struct sftp_conn *conn, const char *path, Attrib *a)
{
	if (sftp_glob_get_attrib(path, a) != 0 &&
	    sftp_stat(conn, path, 1, a) != 0)
		attrib_clear(a);
}

/* HPN: the byte total of the regular files in g, the last sftp_glob
 * result, from the cached attributes, for a -j meter. *nfiles gets their
 * count. A directory is left out: a -r walk adds its own total when it
 * ends, and without -r it is refused. A file of unknown size makes the
 * total 0, so the meter shows a rate only. A path past the cache's cap
 * is such a file. It is not stat'd here, since its transfer stats it. */
off_t
sftp_glob_files_total(const glob_t *g, int *nfiles)
{
	off_t total = 0;
	int i, sized = 1;
	Attrib a;

	*nfiles = 0;
	if (g->gl_pathv == NULL)
		return 0;
	for (i = 0; g->gl_pathv[i] != NULL; i++) {
		if (sftp_globpath_is_dir(g->gl_pathv[i]))
			continue;
		if (sftp_glob_get_attrib(g->gl_pathv[i], &a) != 0 ||
		    !(a.flags & SSH2_FILEXFER_ATTR_SIZE)) {
			sized = 0;
			(*nfiles)++;
			continue;
		}
		/* A broken symlink keeps its lstat attributes. It and any
		 * other non-regular file are refused at submit. */
		if ((a.flags & SSH2_FILEXFER_ATTR_PERMISSIONS) &&
		    !S_ISREG(a.perm))
			continue;
		total += (off_t)a.size;
		(*nfiles)++;
	}
	return sized ? total : 0;
}

static void *
fudge_opendir(const char *path)
{
	struct SFTP_OPENDIR *r;

	r = xcalloc(1, sizeof(*r));

	if (sftp_readdir(cur.conn, path, &r->dir)) {
		free(r);
		return(NULL);
	}

	r->offset = 0;

	return((void *)r);
}

static struct dirent *
fudge_readdir(struct SFTP_OPENDIR *od)
{
	/* Solaris needs sizeof(dirent) + path length (see below) */
	static char buf[sizeof(struct dirent) + MAXPATHLEN];
	struct dirent *ret = (struct dirent *)buf;
#ifdef __GNU_LIBRARY__
	static int inum = 1;
#endif /* __GNU_LIBRARY__ */

	if (od->dir[od->offset] == NULL)
		return(NULL);

	memset(buf, 0, sizeof(buf));

	/*
	 * Solaris defines dirent->d_name as a one byte array and expects
	 * you to hack around it.
	 */
#ifdef BROKEN_ONE_BYTE_DIRENT_D_NAME
	strlcpy(ret->d_name, od->dir[od->offset++]->filename, MAXPATHLEN);
#else
	strlcpy(ret->d_name, od->dir[od->offset++]->filename,
	    sizeof(ret->d_name));
#endif
#ifdef __GNU_LIBRARY__
	/*
	 * Idiot glibc uses extensions to struct dirent for readdir with
	 * ALTDIRFUNCs. Not that this is documented anywhere but the
	 * source... Fake an inode number to appease it.
	 */
	ret->d_ino = inum++;
	if (!inum)
		inum = 1;
#endif /* __GNU_LIBRARY__ */

	return(ret);
}

static void
fudge_closedir(struct SFTP_OPENDIR *od)
{
	sftp_free_dirents(od->dir);
	free(od);
}

static int
fudge_lstat(const char *path, struct stat *st)
{
	Attrib a;

	if (sftp_lstat(cur.conn, path, 1, &a) != 0)
		return -1;

	attrib_cache_record(path, &a);	/* HPN */
	attrib_to_stat(&a, st);

	return 0;
}

static int
fudge_stat(const char *path, struct stat *st)
{
	Attrib a;

	if (sftp_stat(cur.conn, path, 1, &a) != 0)
		return -1;

	attrib_cache_record(path, &a);	/* HPN */
	attrib_to_stat(&a, st);

	return(0);
}

int
sftp_glob(struct sftp_conn *conn, const char *pattern, int flags,
    int (*errfunc)(const char *, int), glob_t *pglob)
{
	int r;
	size_t l;
	char *s;
	struct stat sb;

	pglob->gl_opendir = fudge_opendir;
	pglob->gl_readdir = (struct dirent *(*)(void *))fudge_readdir;
	pglob->gl_closedir = (void (*)(void *))fudge_closedir;
	pglob->gl_lstat = fudge_lstat;
	pglob->gl_stat = fudge_stat;

	attrib_cache_clear();		/* HPN */
	memset(&cur, 0, sizeof(cur));
	cur.conn = conn;

	if ((r = glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob)) != 0)
		return r;
	/*
	 * When both GLOB_NOCHECK and GLOB_MARK are active, a single gl_pathv
	 * entry has been returned and that entry has not already been marked,
	 * then check whether it needs a '/' appended as a directory mark.
	 *
	 * This ensures that a NOCHECK result is annotated as a directory.
	 * The glob(3) spec doesn't promise to mark NOCHECK entries, but doing
	 * it simplifies our callers (sftp/scp) considerably.
	 *
	 * XXX doesn't try to handle gl_offs.
	 */
	if ((flags & (GLOB_NOCHECK|GLOB_MARK)) == (GLOB_NOCHECK|GLOB_MARK) &&
	    pglob->gl_matchc == 0 && pglob->gl_offs == 0 &&
	    pglob->gl_pathc == 1 && (s = pglob->gl_pathv[0]) != NULL &&
	    (l = strlen(s)) > 0 && s[l-1] != '/') {
		if (fudge_stat(s, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			/* NOCHECK on a directory; annotate */
			if ((s = realloc(s, l + 2)) != NULL) {
				memcpy(s + l, "/", 2);
				pglob->gl_pathv[0] = s;
			}
		}
	}
	return 0;
}
