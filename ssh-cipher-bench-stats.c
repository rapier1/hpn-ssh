#include <stdlib.h>
#include <stdio.h>

#include "ssh-cipher-bench-stats.h"

/* set BIL to 0 for maximum possible */
#define BIL  1000000000ull
/* set BIL2 to 0 for maximum possible */
#define BIL2 1000000000000000000ull

#define OK        0
#define OVERFLOW  1
#define UNDERFLOW 2
#define DIVZERO   4

#if BIL2 != 0
#define MAXVAL2 (BIL2 - 1)
#else
#define MAXVAL2 (-1)
#endif

/* A fixed point data type, x is in units of billionths, and shall not exceed
 * one billion.*/
struct fp {
	unsigned long long x;
	unsigned char err;
};

/* Holds products of two 'struct fp's without any loss in precision, or a sum of
 * up to a billion 'struct fp's without any loss in precision. */
struct fp2 {
	unsigned long long w; /* XXXXXXXXXXXXXXXXXX.000000000000000000 */
	unsigned long long f; /* 000000000000000000.XXXXXXXXXXXXXXXXXX */
	unsigned char err;
};

struct cbrecords {
	unsigned long n;
	struct fp * data;
};

/* return a + b */
static struct fp
plus(struct fp a, struct fp b)
{
	struct fp c;

	c.err = a.err | b.err;
	c.x = a.x + b.x;
#if BIL2 != 0
	if ((c.x < a.x) || (c.x < b.x) || c.x >= BIL2) {
#else
	if ((c.x < a.x) || (c.x < b.x)) {
#endif
		c.x = MAXVAL2;
		c.err |= OVERFLOW;
	}
	return c;
}

/* return a + b */
static struct fp2
plus2(struct fp2 a, struct fp2 b)
{
	struct fp2 c;
	unsigned long long halfBIL2;
	int carry;

	c.err = a.err | b.err;

	halfBIL2 = MAXVAL2; /* odd value, e.g. 255 */
	halfBIL2 = halfBIL2 / 2; /* rounds down, e.g. 127.5 -> 127 */
	halfBIL2 = halfBIL2 + 1; /* adjusts to half BIL2, e.g. 127 -> 128 */
	if ((a.f < halfBIL2) && (b.f < halfBIL2)) {
		/* Will not overflow */
		c.f = a.f + b.f;
		carry = 0;
	} else if ((a.f >= halfBIL2) && (b.f < halfBIL2)) {
		/* May overflow */
		/* Temporarily decrease a.f to check for overflow */
		a.f = a.f - halfBIL2;
		c.f = a.f + b.f;
		if (c.f >= halfBIL2) {
			/* Will overflow, so decrease again and carry */
			c.f = c.f - halfBIL2;
			carry = 1;
		} else {
			/* Will not overflow, so undo the decrease */
			c.f = c.f + halfBIL2;
			carry = 0;
		}
	} else if ((a.f < halfBIL2) && (b.f >= halfBIL2)) {
		/* May overflow */
		/* Temporarily decrease b.f to check for overflow */
		b.f = b.f - halfBIL2;
		c.f = a.f + b.f;
		if (c.f >= halfBIL2) {
			/* Will overflow, so decrease again and carry */
			c.f = c.f - halfBIL2;
			carry = 1;
		} else {
			/* Will not overflow, so undo the decrease */
			c.f = c.f + halfBIL2;
			carry = 0;
		}
	} else {
		/* (a.f >= halfBIL2) && (b.f >= halfBIL2)) */
		/* Will overflow */
		/* subtract halfBIL2 from each and carry */
		a.f = a.f - halfBIL2;
		b.f = b.f - halfBIL2;
		c.f = a.f + b.f;
		carry = 1;
	}

	c.w = a.w + b.w;
#if BIL2 != 0
	if ((c.w < a.w) || (c.w < b.w) || (c.w >= BIL2)) {
#else
	if ((c.w < a.w) || (c.w < b.w)) {
#endif
		c.w = MAXVAL2;
		c.f = MAXVAL2;
		c.err |= OVERFLOW;
	}

	if (carry) {
		if (c.w == MAXVAL2) {
			c.f = MAXVAL2;
			c.err |= OVERFLOW;
		} else {
			c.w = c.w + 1;
		}
	}

	return c;
}

/* return a - b */
static struct fp2
minus2(struct fp2 a, struct fp2 b)
{
	struct fp2 c;
	unsigned long long halfBIL2;
	int borrow;

	c.err = a.err | b.err;

	halfBIL2 = MAXVAL2; /* odd value, e.g. 255 */
	halfBIL2 = halfBIL2 / 2; /* rounds down, e.g. 127.5 -> 127 */
	halfBIL2 = halfBIL2 + 1; /* adjusts to half BIL2, e.g. 127 -> 128 */
	if ((a.f >= halfBIL2) && (b.f < halfBIL2)) {
		/* Will not underflow */
		c.f = a.f - b.f;
		borrow = 0;
	} else if ((a.f < halfBIL2) && (b.f < halfBIL2)) {
		/* May underflow */
		/* Temporarily increase a.f to check for underflow */
		a.f = a.f + halfBIL2;
		c.f = a.f - b.f;
		if (c.f < halfBIL2) {
			/* Will underflow, so increase again and borrow */
			c.f = c.f + halfBIL2;
			borrow = 1;
		} else {
			/* Will not underflow, so undo the increase */
			c.f = c.f - halfBIL2;
			borrow = 0;
		}
	} else if ((a.f >= halfBIL2) && (b.f >= halfBIL2)) {
		/* May underflow */
		/* Temporarily decrease b.f to check for underflow */
		b.f = b.f - halfBIL2;
		c.f = a.f - b.f;
		if (c.f < halfBIL2) {
			/* Will underflow, so decrease again and borrow */
			/* decreasing b.f corresponds to increasing c.f */
			c.f = c.f + halfBIL2;
			borrow = 1;
		} else {
			/* Will not underflow, so undo the decrease */
			/* increasing b.f corresponds to decreasing c.f */
			c.f = c.f - halfBIL2;
			borrow = 0;
		}
	} else {
		/* (a.f < halfBIL2) && (b.f >= halfBIL2)) */
		/* Will underflow */
		/* increase a.f, decrease b.f, and borrow */
		a.f = a.f + halfBIL2;
		b.f = b.f - halfBIL2;
		c.f = a.f - b.f;
		borrow = 1;
	}

	if ((b.w > a.w) || ((b.w == a.w) && (b.f > a.f))) {
		c.w = 0;
		c.f = 0;
		c.err |= UNDERFLOW;
		return c;
	}
	c.w = a.w - b.w;

	if (borrow) {
		if (c.w == 0) {
			c.w = 0;
			c.f = 0;
			c.err |= UNDERFLOW;
			return c;
		} else {
			c.w = c.w - 1;
		}
	}
	return c;
}

/* return a / b */
static struct fp2
div2(struct fp2 a, unsigned long b)
{
	struct fp2 c;
	struct fp2 r;

	c.err = a.err;

	if (b == 0) {
		c.w = 0;
		c.f = 0;
		c.err |= DIVZERO;
		return c;
	}

	/*
	 * This is basically just long division:
	 *
	 *       (c.w_hi) (c.w_lo).(c.f_hi) (c.f_lo)
	 *      ____________________________________
	 *   b ) (a.w_hi) (a.w_lo).(a.f_hi) (a.f_lo)
	 */

	c.w = a.w / b; /* whole part */
	r.w = a.w % b; /* remainder --> needed for fractional part */
	r.f = a.f;
	/* overflow tracking: r.w <= b - 1 <= BIL - 1 */

	/*
	 *       (c.w_hi) (c.w_lo).???????? ????????
	 *      ____________________________________
	 *   b ) (a.w_hi) (a.w_lo).(a.f_hi) (a.f_lo)
	 *                (remain).(a.f_hi) (a.f_lo)  == r
	 *                        ^
	 */

	/* left-shift values by a factor of BIL */
	r.w = r.w * BIL;
	/* overflow tracking: r.w <= BIL * b - BIL <= BIL2 - BIL */
	/* overflow tracking: r.f <= BIL2 - 1 */
	/* overflow tracking: r.f / BIL <= BIL - 1 */
	r.w = r.w + (r.f / BIL);
	/* overflow tracking: r.w <= BIL * b - 1 <= BIL2 - 1*/
	/* overflow tracking: r.f % BIL <= BIL - 1 */
	r.f = BIL * (r.f % BIL);
	/* overflow tracking: r.f <= BIL2 - BIL */

	/*
	 *       (c.w_hi) (c.w_lo).???????? ????????
	 *      ____________________________________
	 *   b ) (a.w_hi) (a.w_lo).(a.f_hi) (a.f_lo)
	 *                (remain) (a.f_hi).(a.f_lo)  == r
	 *                                 ^
	 */

	/* overflow tracking: r.w / b <= BIL - 1 */
	c.f = BIL * (r.w / b);
	/* overflow tracking: c.f <= BIL2 - BIL */
	r.w = r.w % b; /* remainder */
	/* overflow tracking: r.w <= b - 1 <= BIL - 1 */

	/*
	 *       (c.w_hi) (c.w_lo).(c.f_hi) ????????
	 *      ____________________________________
	 *   b ) (a.w_hi) (a.w_lo).(a.f_hi) (a.f_lo)
	 *                (remain) (a.f_hi).(a.f_lo)
	 *                         (remain).(a.f_lo)  == r
	 *                                 ^
	 */

	/* left-shift values by a factor of BIL */
	r.w = r.w * BIL;
	/* overflow tracking: r.w <= BIL * b - BIL <= BIL2 - BIL */
	/* overflow tracking: r.f <= BIL2 - BIL */
	/* overflow tracking: r.f / BIL <= BIL - 1 */
	r.w = r.w + (r.f / BIL);
	/* overflow tracking: r.w <= BIL * b - 1 <= BIL2 - 1 */
	/* no need to left-shift r.f % BIL, since it's known to be zero */

	/*
	 *       (c.w_hi) (c.w_lo).(c.f_hi) ????????
	 *      ____________________________________
	 *   b ) (a.w_hi) (a.w_lo).(a.f_hi) (a.f_lo)
	 *                (remain) (a.f_hi).(a.f_lo)
	 *                         (remain) (a.f_lo). == r
	 *                                          ^
	 */

	/* overflow tracking: c.f <= BIL2 - BIL */
	/* overflow tracking: r.w / b <= BIL - 1 */
	c.f = c.f + (r.w / b);
	/* overflow tracking: c.f <= BIL2 - 1 */
	/* r.w % b --> dicarded */

	/*
	 *       (c.w_hi) (c.w_lo).(c.f_hi) (c.f_lo)
	 *      ____________________________________
	 *   b ) (a.w_hi) (a.w_lo).(a.f_hi) (a.f_lo)
	 *                (remain) (a.f_hi).(a.f_lo)
	 *                         (remain) (a.f_lo).
	 *                                  (remain). --> discarded
	 */

	return c;
}

/* return a */
static struct fp2
promote(struct fp a)
{
	struct fp2 b;

	b.err = a.err;

	b.w = a.x / BIL;
	b.f = BIL * (a.x % BIL);

	return b;
}

/* return a * b */
static struct fp2
mult(struct fp a, struct fp b)
{
	struct fp2 c;
	struct fp xab, xba;
	unsigned long long aw, af, bw, bf;

	c.err = a.err | b.err;
	xab.err = xba.err = OK;

	aw = a.x / BIL;
	af = a.x % BIL;
	bw = b.x / BIL;
	bf = b.x % BIL;

	c.f = af * bf;
	c.w = aw * bw;

	xab.x = aw * bf;
	xba.x = bw * af;

	c = plus2(c,promote(xab));
	c = plus2(c,promote(xba));

	return c;
}

/* return a * a */
static struct fp2
square(struct fp a)
{
	return mult(a,a);
}

/* return a * b */
static struct fp2
mult2(struct fp2 a, struct fp2 b)
{
	struct fp2 c, cw, cf;
	struct fp aw, af, bw, bf;

	c.err = a.err | b.err;
	aw.err = af.err = a.err;
	bw.err = bf.err = b.err;

	aw.x = a.w;
	af.x = a.f;
	bw.x = b.w;
	bf.x = b.f;

	cw = mult(aw,bw);
	c.w = cw.f;
	c.err |= cw.err;

	cf = mult(af,bf);
	c.f = cf.w;
	c.err |= cw.err;

	c = plus2(c,mult(aw,bf));
	c = plus2(c,mult(af,bw));

	return c;
}

/* return a * b */
static struct fp2
scale(struct fp2 a, unsigned long b)
{
	struct fp2 c, b2;

	b2.err = OK;

	b2.w = b;
	b2.f = 0;

	c = mult2(a,b2);

	return c;
}

/* return a <= b */
static int
le(struct fp2 a, struct fp2 b)
{
	if (a.w == b.w)
		return (a.f <= b.f);
	else
		return (a.w < b.w);
}

/* return a / 2 */
static struct fp
half(struct fp a)
{
	struct fp b;

	b.err = a.err;

	b.x = a.x / 2;

	return b;
}

/* return sqrt(a) */
static struct fp
root(struct fp2 a)
{
	struct fp l, m, r;

	l.err = m.err = r.err = OK;
	l.x = 0;
	r.x = MAXVAL2;
	
	while (l.x != r.x) {
		m = plus(half(l),half(r));
		/* correct the rounding, and round up */
		if (((l.x % 2) == 1) || ((r.x % 2) == 1))
			m.x = m.x + 1;

		if (le(square(m), a)) {
			l = m;
		} else {
			r = m;
			r.x = r.x - 1;
		}
	}

	l.err |= a.err;

	return l;
}

struct cbrecords *
initRecs(unsigned long n)
{
	struct cbrecords * recs;

	recs = malloc(sizeof(struct cbrecords));
	if (recs == NULL)
		return NULL;
	recs->n = n;
	recs->data = calloc(n, sizeof(struct fp));
	if (recs->data == NULL) {
		free(recs);
		return NULL;
	}
	return recs;
}

void
freeRecs(struct cbrecords * recs)
{
	if (recs == NULL)
		return;
	if (recs->data != NULL) {
		free(recs->data);
		recs->data = NULL;
	}
	free(recs);
}

int
record(struct cbrecords * recs, unsigned long position, unsigned long start_w,
    unsigned long start_f, unsigned long stop_w, unsigned long stop_f)
{
	unsigned long long start;
	unsigned long long stop;

	if (recs == NULL)
		return 1;

	if (position >= recs->n)
		return 1;

	start = start_w;
	start = start * BIL;
	start = start + start_f;
	
	stop = stop_w;
	stop = stop * BIL;
	stop = stop + stop_f;

	if (stop < start)
		return 1;

	recs->data[position].x = stop - start;
	recs->data[position].err = OK;
	return 0;
}

static void
checkError(unsigned char err)
{
	if (err & OVERFLOW)
		fprintf(stderr, "Error: An arithmetic overflow occurred.\n");
	if (err & UNDERFLOW)
		fprintf(stderr, "Error: An arithmetic underflow occurred.\n");
	if (err & DIVZERO)
		fprintf(stderr, "Error: Tried to divide by zero.\n");
	if (err != OK)
		exit(1);
}

struct cbstats
getStats(struct cbrecords * recs, unsigned int nbins) {
	struct cbstats stats;
	struct fp2 avg, sum, sumsq;
	struct fp min, max, std;
	double binwidth;
	unsigned int bin;

	sum.w = sum.f = sumsq.w = sumsq.f = 0;
	min.x = MAXVAL2;
	max.x = 0;
	sum.err = sumsq.err = min.err = max.err = OK;

	for (unsigned long i = 0; i < recs->n; i++) {
		sum = plus2(sum, promote(recs->data[i]));
		checkError(sum.err);
		sumsq = plus2(sumsq, square(recs->data[i]));
		checkError(sumsq.err);
		if (recs->data[i].x < min.x)
			min = recs->data[i];
		if (recs->data[i].x > max.x)
			max = recs->data[i];
	}
	avg = div2(sum, recs->n);
	checkError(avg.err);
	if (avg.w >= BIL)
		checkError(OVERFLOW);

	std = root(
		div2(div2(
			minus2(
				scale(sumsq, recs->n),
				mult2(sum, sum)
			),
		recs->n), recs->n)
	);
	stats.avg = (avg.w * BIL) + (avg.f / BIL);
	stats.std = std.x;
	stats.min = min.x;
	stats.max = max.x;

	if (stats.avg > (2 * stats.std))
		stats.firstbin = stats.avg - (2 * stats.std);
	else
		stats.firstbin = stats.min;
	if (stats.firstbin < stats.min)
		stats.firstbin = stats.min;
	
	if (stats.avg < (MAXVAL2 - (2 * stats.std)))
		stats.lastbin = stats.avg + (2 * stats.std);
	else
		stats.lastbin = stats.max;
	if (stats.lastbin > stats.max)
		stats.lastbin = stats.max;

	if (nbins > 0) {
		stats.bins = calloc(nbins, sizeof(*(stats.bins)));
	
		binwidth = ((double) (stats.lastbin - stats.firstbin)) /
		    ((double) nbins);
		for (unsigned int i = 0; i < nbins; i++)
			stats.bins[i] = 0;
		for (unsigned long i = 0; i < recs->n; i++) {
			if ((recs->data[i].x > stats.firstbin) &&
			    (recs->data[i].x < stats.lastbin)) {
				bin = (unsigned int) (((double) (recs->data[i].x
				- stats.firstbin)) / binwidth);
				if (bin >= nbins)
					bin = bin - 1;
				if (bin < 0)
					bin = bin + 1;
				if ((bin >= nbins) || (bin < 0)) {
					fprintf(stderr,
					    "Bad bin calculated!\n");
				} else {
					stats.bins[bin]++;
				}
			}
		}
	}

	return stats;
}
