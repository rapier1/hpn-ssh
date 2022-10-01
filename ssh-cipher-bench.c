#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <argp.h>
#include <sys/time.h>

/* Need to ignore openbsd_compat/getopt.h */
#define _GETOPT_H_

#include "includes.h"

#include "cipher.h"

#define NANO 1000000000

const char * argp_program_version = "ssh-cipher-bench 1.0";
const char * argp_program_bug_address = "<mwd@psc.edu>";

static char doc[] = "A benchmarking tool for SSH ciphers.";

static struct argp_option options[] = {
	{"ciphers", 'c', "cipher_list", 0,
	    "comma-separated list of ciphers to benchmark"},
	{"num",     'n', "N", 0, "benchmark each cipher with N packets"},
	{"quiet",   'q', 0, 0, "don't print the table header"},
	{ 0 }
};

struct arguments {
	int quiet;
	uint32_t n;
	char * cipherList;
};

static error_t parse_opt(int key, char * arg, struct argp_state * state) {
	struct arguments * arguments = state->input;

	switch(key) {
		case 'c':
			arguments->cipherList = arg;
			break;
		case 'n':
			arguments->n = atoi(arg);
			break;
		case 'q':
			arguments->quiet = 1;
			break;
		case ARGP_KEY_ARG:
			argp_usage (state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = {options, parse_opt, 0, doc};

void listciphers() {
	char * cipherlist;

	cipherlist = NULL;
	cipherlist = cipher_alg_list('\n', 0);
	if (cipherlist != NULL) {
		fprintf(stderr, "Valid ciphers:\n");
		printf("%s\n", cipherlist);
		free(cipherlist);
	} else {
		fprintf(stderr, "Could not get list of valid ciphers.\n");
	}
}

unsigned int pad(unsigned int len, unsigned int blocksize) {
	unsigned int padding;

	padding = blocksize - (len % blocksize);

	if (padding < 4)
		padding += blocksize;

	return padding;
}

void normalize(struct timespec * t) {
	while (t->tv_nsec > NANO) {
		t->tv_sec += 1;
		t->tv_nsec -= NANO;
	}
	while (t->tv_nsec < 0) {
		if (t->tv_sec == 0)
			fprintf(stderr, "Warning! Negative time detected!\n");
		t->tv_sec -= 1;
		t->tv_nsec += NANO;
	}
}

struct timespec plus(struct timespec a, struct timespec b) {
	struct timespec c;
	c.tv_sec = a.tv_sec + b.tv_sec;
	c.tv_nsec = a.tv_nsec + b.tv_nsec;
	normalize(&c);
	return c;
}

struct timespec minus(struct timespec a, struct timespec b) {
	struct timespec c;
	c.tv_sec = a.tv_sec - b.tv_sec;
	c.tv_nsec = a.tv_nsec - b.tv_nsec;
	normalize(&c);
	return c;
}

struct timespec time_div(struct timespec a, uint32_t b) {
	struct timespec c;
	unsigned long long d;

	c.tv_sec = a.tv_sec / b;
	d = 0;
	d = d + (a.tv_sec % b);
	d = d * NANO;
	d = d + a.tv_nsec;
	d = d / b;
	if (d > NANO)
		fprintf(stderr, "Overflow!\n");
	c.tv_nsec = d % NANO;

	return c;
}

struct bignum {
	unsigned long long s;
	unsigned long long ns;
	unsigned long long nns;
};

void bignormalize(struct bignum * b) {
	if (b->ns > NANO) {
		b->s += (b->ns / NANO);
		b->ns %= NANO;
	}
	if (b->nns > NANO) {
		b->ns += (b->nns / NANO);
		b->nns %= NANO;
	}
	if (b->ns > NANO) {
		b->s += (b->ns / NANO);
		b->ns %= NANO;
	}
}

struct bignum bigdiv(struct bignum a, uint32_t b) {
	struct bignum c;

	c.s = a.s / b;
	c.ns = a.s % b;
	c.ns *= NANO;
	c.ns += a.ns;
	c.nns = c.ns % b;
	c.ns /= b;
	c.nns *= NANO;
	c.nns += a.nns;
	c.nns /= b;
	bignormalize(&c);
	return c;
}

int bigLessThanOrEqual(struct bignum a, struct bignum b) {
	if (a.s != b.s)
		return (a.s < b.s);
	if (a.ns != b.ns)
		return (a.ns < b.ns);
	return (a.nns <= b.nns);
}

struct bignum mult(struct timespec a, struct timespec b) {
	struct bignum c;
	unsigned long long as, ans, bs, bns;

	as = a.tv_sec;
	bs = b.tv_sec;
	ans = a.tv_nsec;
	bns = b.tv_nsec;

	c.s = as * bs;
	c.ns = (as * bns) + (bs * ans);
	c.nns = ans * bns;

	bignormalize(&c);
	return c;
}

struct timespec halve(struct timespec a) {
	struct timespec b;

	b.tv_sec = a.tv_sec / 2;
	b.tv_nsec = a.tv_nsec / 2;
	if (a.tv_sec % 2 != 0)
		b.tv_nsec += (NANO/2);
	normalize(&b);
	return b;
}

struct timespec next(struct timespec a) {
	a.tv_nsec += 1;
	normalize(&a);
	return a;
}

int time_equal(struct timespec a, struct timespec b) {
	if (a.tv_sec == b.tv_sec)
		return (a.tv_nsec == b.tv_nsec);
	return 0;
}

struct timespec bigroot(struct bignum a) {
	struct timespec l, m, r, oldr;
	l.tv_sec = 0;
	r.tv_sec = oldr.tv_sec = 1;
	l.tv_nsec = r.tv_nsec = oldr.tv_nsec = 0;

	while (bigLessThanOrEqual(mult(r, r), a)) {
		oldr.tv_sec = r.tv_sec;
		r.tv_sec *= 2;
		if (r.tv_sec < oldr.tv_sec) {
			fprintf(stderr, "Overflow during root-finding.\n");
			exit(1);
		}
	}

	while (! time_equal(next(l), r)) {
		m = plus(l, r);
		m = halve(m);
		if (m.tv_sec < l.tv_sec || m.tv_sec > r.tv_sec) {
			fprintf(stderr, "Overflow during root-finding.\n");
			exit(1);
		}

		if (bigLessThanOrEqual(mult(m, m), a))
			l = m;
		else
			r = m;
	}

	return l;
}

int test(unsigned int maxstrlen, char * arg, uint32_t n) {
	struct sshcipher * c;
	struct sshcipher_ctx * ctx;
	unsigned int keylen, ivlen;
	unsigned char * key, * iv;
	unsigned int blocksize, aadlen, len, authlen;
	unsigned char * src, * dest;
	uint32_t counter;
	unsigned char no_opt;
	struct timespec * starts, * stops;
	struct timespec * start, * stop;
	struct timespec avg, stddev, delta;
	struct bignum vari, dvari;
	unsigned long long ts, tns;
	double speed;
	
	c = NULL;
	ctx = NULL;
	keylen = ivlen = 0;
	key = iv = NULL;
	blocksize = aadlen = len = authlen = 0;
	src = dest = NULL;
	counter = 0;
	no_opt = 4; /* doesn't matter */
	starts = stops = NULL;
	start = stop = NULL;
	avg.tv_sec = stddev.tv_sec = delta.tv_sec = 0;
	avg.tv_nsec = stddev.tv_nsec = delta.tv_nsec = 0;
	vari.s = vari.ns = vari.nns = 0;
	dvari.s = dvari.ns = dvari.nns = 0;
	ts = tns = 0;

	c = cipher_by_name(arg);
	if (c == NULL) {
		fprintf(stderr, "Cipher \"%s\" not recognized.\n", arg);
		return 1;
	}

	blocksize = cipher_blocksize(c);
	aadlen = 4;
	len = 0;
	len += 1;                   /* uint8_t  : amount of padding    */
	len += 1;                   /* uint8_t  : packet type          */
	len += 4;                   /* uint32_t : remote_id            */
	len += 4;                   /* uint32_t : packet payload size  */
	len += SSH_IOBUFSZ;         /* <varies> : packet payload (max) */
	len += pad(len, blocksize); /* <varies> : padding              */
	authlen = cipher_authlen(c);

	src  = calloc((aadlen + len), sizeof(*src));
	if (src == NULL) {
		fprintf(stderr,
		    "Could not allocate memory for source buffer.\n");
		goto fail;
	}

	dest = calloc((aadlen + len + authlen), sizeof(*dest));
	if (dest == NULL) {
		fprintf(stderr,
		    "Could not allocate memory for destination buffer.\n");
		goto fail;
	}

	keylen = cipher_keylen(c);
	if (keylen > 0) {
		key = malloc(keylen * sizeof(*key));
		if (key == NULL) {
			fprintf(stderr, "Could not allocate memory for key.\n");
			goto fail;
		}
		memset(key, 85, keylen * sizeof(*key));
	}
	
	ivlen = cipher_ivlen(c);
	if (ivlen > 0) {
		iv = malloc(ivlen * sizeof(*iv));
		if (iv == NULL) {
			fprintf(stderr, "Could not allocate memory for iv.\n");
			goto fail;
		}
		memset(iv, 73, ivlen * sizeof(*iv));
	}

	if (cipher_init(&ctx, c, key, keylen, iv, ivlen, 1, 1) != 0) {
		fprintf(stderr, "Could not initialize the cipher.\n");
		goto fail;
	}
	free(key);
	key = NULL;
	free(iv);
	iv = NULL;

	starts = calloc(n, sizeof(*starts));
	if (starts == NULL) {
		fprintf(stderr, "Could not allocate memory for start times.\n");
		goto fail;
	}

	stops = calloc(n, sizeof(*stops));
	if (stops == NULL) {
		fprintf(stderr, "Could not allocate memory for stop times.\n");
		goto fail;
	}

	for (counter = 0; counter < n; counter++) {
		start = &(starts[counter]);
		stop = &(stops[counter]);
		clock_gettime(CLOCK_REALTIME, start);
		cipher_crypt(ctx, counter, dest, src, len, aadlen, authlen);
		clock_gettime(CLOCK_REALTIME, stop);
		no_opt += dest[15];
	}

	cipher_free(ctx);
	ctx = NULL;
	free(src);
	src = NULL;
	free(dest);
	dest = NULL;

	for (counter = 0; counter < n; counter++) {
		start = &(starts[counter]);
		stop = &(stops[counter]);
		normalize(stop);
		normalize(start);

		delta = minus(*stop, *start);
		avg = plus(avg, delta);
		
		ts = delta.tv_sec;
		tns = delta.tv_nsec;
		vari.s += ts * ts;
		vari.ns += 2 * ts * tns;
		vari.nns += tns * tns;
		bignormalize(&vari);
	}
	vari.nns *= n;
	vari.ns *= n;
	vari.s *= n;
	bignormalize(&vari);
	ts = avg.tv_sec;
	tns = avg.tv_nsec;

	dvari.s = ts * ts;
	dvari.ns = 2 * ts * tns;
	dvari.nns = tns * tns;
	bignormalize(&dvari);

	if (vari.s < dvari.s) {
		fprintf(stderr, "avg(x^2) < (avg(x))^2\n");
	}
	vari.s -= dvari.s;
	while (vari.ns < dvari.ns) {
		if (vari.s == 0)
			fprintf(stderr, "avg(x^2) < (avg(x))^2\n");
		vari.s -= 1;
		vari.ns += NANO;
	}
	vari.ns -= dvari.ns;
	while (vari.nns < dvari.nns) {
		if (vari.ns == 0) {
			if (vari.s == 0)
				fprintf(stderr, "avg(x^2) < (avg(x))^2\n");
			vari.s -= 1;
			vari.ns += NANO;
		}
		vari.ns -= 1;
		vari.nns += NANO;
	}
	vari.nns -= dvari.nns;
	bignormalize(&vari);

	avg = time_div(avg, n);
	vari = bigdiv(vari, n);
	vari = bigdiv(vari, n);

	stddev = bigroot(vari);

	printf("%-*s ", maxstrlen, arg);
	if (avg.tv_sec > 0)
		printf("%2ld%9lu ", avg.tv_sec, avg.tv_nsec);
	else
		printf("  %9lu ", avg.tv_nsec);
	if (stddev.tv_sec > 0)
		printf("%2ld%9lu ", stddev.tv_sec, stddev.tv_nsec);
	else
		printf("  %9lu ", stddev.tv_nsec);

	speed = avg.tv_nsec;
	speed /= NANO;
	speed += avg.tv_sec;
	speed /= 32768; /* packet size */
	speed *= 1073741824; /* 1 GiB */
	speed = 1/speed;
	printf("%12.6lf ", speed);
	speed *= 8;
	printf("%12.6lf ", speed);
	printf("%3hhu\n", no_opt);
	free(starts);
	starts = NULL;
	free(stops);
	stops = NULL;
	return 0;
 fail:
	if (ctx != NULL)
		cipher_free(ctx);
	if (key != NULL)
		free(key);
	if (iv != NULL)
		free(iv);
	if (src != NULL)
		free(src);
	if (dest != NULL)
		free(dest);
	if (starts != NULL)
		free(starts);
	if (stops != NULL)
		free(stops);
	return 1;
}

int testList(char * cipherlist, uint32_t n, int quiet) {
	char * cursor, * header;
	unsigned int maxstrlen, curstrlen;
	
	maxstrlen = 0;
	curstrlen = 0;
	for (int i=0; cipherlist[i] != '\0'; i++) {
		if ( cipherlist[i] != ',' )
			curstrlen++;
		else {
			if (curstrlen > maxstrlen)
				maxstrlen = curstrlen;
			curstrlen = 0;
		}
	}
	if (curstrlen > maxstrlen)
		maxstrlen = curstrlen;

	if(maxstrlen < 6)
		maxstrlen = 6;

	if (!quiet) {
		printf("%-*s %11s %11s %12s %12s %3s\n",maxstrlen, "cipher",
		    "avg. (ns)", "stdev. (ns)", "rate (GiB/s)", "rate (Gib/s)",
		    "!op");
		header = malloc((maxstrlen + 55) * sizeof(*header));
		sprintf(header,"%*s|%11s|%11s|%12s|%12s|%3s",maxstrlen, "", "",
		    "", "", "", "");
		for (unsigned int i = 0; i < maxstrlen + 55; i++) {
			if (header[i] == ' ')
				header[i] = '-';
			else if (header[i] == '|')
				header[i] = ' ';
		}
		printf("%s\n",header);
		free(header);
	}

	cursor = cipherlist;
	for (int i = 0; cipherlist[i] != '\0'; i++) {
		if (cipherlist[i] == ',') {
			cipherlist[i] = '\0';
			if (test(maxstrlen, cursor, n) != 0)
				return 1;
			cursor = &(cipherlist[i+1]);
		}
	}
	if (test(maxstrlen, cursor, n) != 0)
		return 1;

	return 0;
}

int main(int argc, char ** argv) {
	struct arguments arguments;
	char * cipherList;
	int retval;

	arguments.quiet = 0;
	arguments.n = 1024;
	arguments.cipherList = NULL;
	cipherList = NULL;

	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	if (arguments.cipherList == NULL) {
		cipherList = cipher_alg_list(',', 0);
		if (cipherList == NULL) {
			fprintf(stderr,
			    "Could not get list of valid ciphers.\n");
			exit(1);
		}
	} else {
		cipherList = strdup(arguments.cipherList);
		if (cipherList == NULL) {
			fprintf(stderr,
			    "Could not allocate memory for the cipher list.\n");
			exit(1);
		}
	}
	retval = testList(cipherList, arguments.n, arguments.quiet);
	free(cipherList);
	exit(retval);
}
