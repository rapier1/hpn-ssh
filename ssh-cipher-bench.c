#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <argp.h>
#include <sys/time.h>

/* Need to ignore openbsd_compat/getopt.h */
#define _GETOPT_H_

#include "includes.h"

#include "cipher.h"
#include "ssh-cipher-bench-stats.h"

#define NANO 1000000000

const char * argp_program_version = "ssh-cipher-bench 1.0";
const char * argp_program_bug_address = "<mwd@psc.edu>";

static char doc[] = "A benchmarking tool for SSH ciphers.";

static struct argp_option options[] = {
	{"ciphers", 'c', "cipher_list", 0,
	    "comma-separated list of ciphers to benchmark"},
	{"3des", 'd', 0, 0,
	    "enable the \"3des-cbc\" cipher, which is normally skipped"},
	{"graph", 'g', "WIDTH", OPTION_ARG_OPTIONAL, "enable graphs in output, "
	    "with a display width of WIDTH characters, where WIDTH is at least "
	    "3; WIDTH defaults to 80"},
	{"num",     'n', "N", 0, "benchmark each cipher with N packets; "
	    "N defaults to 1024"},
	{"packetsize", 'p', "L", 0,
	    "use packets of length L bytes, not exceeding L=SSH_IOBUFSZ, "
	    "where SSH_IOBUFSZ is usually 32768; L defaults to SSH_IOBUFSZ"},
	{"quiet",   'q', 0, 0, "don't print the table header"},
	{ 0 }
};

struct arguments {
	int quiet;
	int des;
	unsigned int nbins;
	uint32_t n;
	uint32_t ps;
	char * cipherList;
};

static error_t parse_opt(int key, char * arg, struct argp_state * state) {
	struct arguments * arguments = state->input;
	int i = 0;

	switch(key) {
		case 'c':
			arguments->cipherList = arg;
			break;
		case 'd':
			arguments->des = 1;
			break;
		case 'g':
			if (arg != NULL) {
				i = atoi(arg);
				if (i < 3)
					argp_error(state,
					    "WIDTH must be at lest 3.");
				arguments->nbins = i - 2;
			} else {
				arguments->nbins = 80 - 2;
			}
			break;
		case 'n':
			i = atoi(arg);
			if (i <= 0)
				argp_error(state,
				    "N must be a positive integer.");
			arguments->n = i;
			break;
		case 'p':
			i = atoi(arg);
			if (i < 0)
				argp_error(state,
				    "L must be a non-negative integer.");
			if (i > SSH_IOBUFSZ) {
				fprintf(stderr,
				    "NOTE: The packet size cannot exceed "
				    "SSH_IOBUFSZ, which is %u.\n"
				    "      Benchmarks will be run with the "
				    "maximum packet size of %u bytes.\n",
				    SSH_IOBUFSZ, SSH_IOBUFSZ);
				i = SSH_IOBUFSZ;
			}

			arguments->ps = i;
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

int test(unsigned int maxstrlen, char * arg, uint32_t n, uint32_t ps,
    unsigned int nbins, char * header) {
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
	double speed;
	struct cbrecords * recs;
	struct cbstats stats;
	
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
	len += ps;         /* <varies> : packet payload (max) */
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

	recs = initRecs(n);

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
		start->tv_sec += start->tv_nsec / 1000000000ull;
		start->tv_nsec %= 1000000000ull;
		stop->tv_sec += stop->tv_nsec / 1000000000ull;
		stop->tv_nsec %= 1000000000ull;
		record(recs, counter, start->tv_sec, start->tv_nsec,
		    stop->tv_sec, stop->tv_nsec);
	}
	stats = getStats(recs, nbins);

	speed = stats.avg;
	speed /= 1000000000;
	speed *= 1073741824; /* 1 GiB */
	speed = ps/speed;
	if ((header != NULL) && (nbins > 0))
		printf("%s\n", header);
	if ((header != NULL) || (nbins == 0))
		printf(
		    "%-*s %11llu %11llu %11llu %11llu %12.6lf %12.6lf %3hhu\n",
		    maxstrlen, arg, stats.min, stats.max, stats.avg, stats.std,
		    speed, speed * 8, no_opt);
	else
		printf("%s (%hhu)\n", arg, no_opt);

	if (nbins > 0) {
		unsigned long binmax = 0;
		for (unsigned int i = 0; i < nbins; i++)
			if (stats.bins[i] > binmax)
				binmax = stats.bins[i];

		#define HEIGHT 5

		double density = binmax / HEIGHT;

		char bingrid[nbins][HEIGHT];
		for (int i = 0; i < HEIGHT; i++)
			for (unsigned int j = 0; j < nbins; j++)
				bingrid[j][i] = ' ';
		for (unsigned int i = 0; i < nbins; i++) {
			double barheight = stats.bins[i] / density;
			for (long unsigned int j = 0;
			    (j < barheight) && (j < HEIGHT); j++) {
				double blockheight = barheight - j;
				if (blockheight >= 15.0/16.0)
					bingrid[i][j] = '8';
				else if (blockheight >= 13.0/16.0)
					bingrid[i][j] = '7';
				else if (blockheight >= 11.0/16.0)
					bingrid[i][j] = '6';
				else if (blockheight >=  9.0/16.0)
					bingrid[i][j] = '5';
				else if (blockheight >=  7.0/16.0)
					bingrid[i][j] = '4';
				else if (blockheight >=  5.0/16.0)
					bingrid[i][j] = '3';
				else if (blockheight >=  3.0/16.0)
					bingrid[i][j] = '2';
				else if (blockheight >=  1.0/16.0)
					bingrid[i][j] = '1';
			}
		}

		printf(" ");
		for (unsigned int i = 0; i < nbins; i++)
			printf("_");
		printf("\n");

		for (int i = HEIGHT - 1; i >= 0; i--) {
			printf("|");
			for (unsigned int j = 0; j < nbins; j++) {
				if ((bingrid[j][i] >= '1') &&
				    (bingrid[j][i] <= '8'))
					printf("\xe2\x96%c",
					    bingrid[j][i] - 0x30 + 0x80);
				else
					printf("%c", bingrid[j][i]);
			}
			printf("|\n");
		}

		char fbinstr[12];
		char lbinstr[12];
		sprintf(fbinstr, "%llu", stats.firstbin);
		sprintf(lbinstr, "%llu", stats.lastbin);
		if (nbins > (strlen(fbinstr) + strlen(lbinstr)))
			printf(" %s%*s%s\n\n", fbinstr,
			    nbins - (int) (strlen(fbinstr) + strlen(lbinstr)),
			    "", lbinstr);
		else
			printf("%s - %s\n\n", fbinstr, lbinstr);
		free(stats.bins);
	}

	freeRecs(recs);
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

int testList(char * cipherlist, uint32_t n, uint32_t ps, int quiet,
    unsigned int nbins) {
	char * cursor, * header;
	unsigned int maxstrlen, curstrlen;
	
	header = NULL;
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
		header = malloc(2 * (maxstrlen + 79) * sizeof(*header));
		sprintf(header,"%-*s %11s %11s %11s %11s %12s %12s %3s\n"
		    "%*s|%11s|%11s|%11s|%11s|%12s|%12s|%3s", maxstrlen,
		    "cipher", "min. (ns)", "max. (ns)", "avg. (ns)",
		    "std. (ns)", "rate (GiB/s)", "rate (Gib/s)", "!op",
		    maxstrlen, "", "", "", "", "", "", "", "");
		for (unsigned int i = maxstrlen + 79; i < 2*(maxstrlen + 79);
		    i++) {
			if (header[i] == ' ')
				header[i] = '-';
			else if (header[i] == '|')
				header[i] = ' ';
		}
		if (nbins == 0)
			printf("%s\n",header);
	}

	cursor = cipherlist;
	for (int i = 0; cipherlist[i] != '\0'; i++) {
		if (cipherlist[i] == ',') {
			cipherlist[i] = '\0';
			if (strlen(cursor) != 0)
				if (test(maxstrlen, cursor, n, ps, nbins,
				    header) != 0)
					return 1;
			cursor = &(cipherlist[i+1]);
		}
	}
	if (strlen(cursor) != 0)
		if (test(maxstrlen, cursor, n, ps, nbins, header) != 0)
			return 1;
	if (header != NULL)
		free(header);

	return 0;
}

int main(int argc, char ** argv) {
	struct arguments arguments;
	char * cipherList;
	int retval;

	arguments.quiet = 0;
	arguments.n = 1024;
	arguments.des = 0;
	arguments.nbins = 0;
	arguments.ps = SSH_IOBUFSZ;
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
		if (arguments.des != 1)
			for (char * c = strstr(cipherList,"3des-cbc");
			    *c != ','; c++)
				*c = ',';
	} else {
		cipherList = strdup(arguments.cipherList);
		if (cipherList == NULL) {
			fprintf(stderr,
			    "Could not allocate memory for the cipher list.\n");
			exit(1);
		}
	}
	retval = testList(cipherList, arguments.n, arguments.ps,
	    arguments.quiet, arguments.nbins);
	free(cipherList);
	exit(retval);
}
