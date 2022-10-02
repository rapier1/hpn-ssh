#ifndef SSH_CIPHER_BENCH_STATS_H
#define SSH_CIPHER_BENCH_STATS_H

#define NBINS 72

struct cbrecords;

struct cbstats {
	unsigned long long avg;
	unsigned long long std;
	unsigned long long min;
	unsigned long long max;
	unsigned long long firstbin;
	unsigned long long lastbin;
	unsigned long bins[NBINS];
};

struct cbrecords * initRecs(unsigned long n);
void freeRecs(struct cbrecords * recs);
int record(struct cbrecords * recs, unsigned long position,
    unsigned long start_w, unsigned long start_f, unsigned long stop_w,
    unsigned long stop_f);
struct cbstats getStats(struct cbrecords * recs);

#endif /* SSH_CIPHER_BENCH_STATS_H */
