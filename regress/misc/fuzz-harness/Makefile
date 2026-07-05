# NB. libssh and libopenbsd-compat should be built with the same sanitizer opts.
CC=clang-19
CXX=clang++-19
FUZZ_FLAGS=-fsanitize=address,fuzzer -fno-omit-frame-pointer
FUZZ_LIBS=-L/usr/lib/llvm-19/lib -lFuzzer

CFLAGS=-D_GNU_SOURCE=1 -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-exceptions -Wno-deprecated -I ../../..
CXXFLAGS=$(CFLAGS) $(FUZZ_FLAGS)
LDFLAGS=-L ../../.. -L ../../../openbsd-compat -g
COMMON_OBJS=../../../ssh-pkcs11-client.o
LIBS=$(COMMON_OBJS) -lssh -lopenbsd-compat -lmd -lcrypto -lfido2 -lcbor $(FUZZ_LIBS)
SK_NULL_OBJS=ssh-sk-null.o
COMMON_DEPS=../../../libssh.a $(COMMON_OBJS)

TARGETS=pubkey_fuzz sig_fuzz authopt_fuzz authkeys_fuzz sshsig_fuzz \
	sshsigopt_fuzz privkey_fuzz kex_fuzz agent_fuzz \
	mkcorpus_sntrup761 sntrup761_enc_fuzz sntrup761_dec_fuzz \
	sftp_fs_info_fuzz \
	sftp_tar_parser_fuzz sftp_bundle_fetch_parse_fuzz \
	mkcorpus_sftp_fs_info mkcorpus_sftp_tar_parser \
	mkcorpus_sftp_bundle_fetch_parse

all: $(TARGETS)

.cc.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

pubkey_fuzz: pubkey_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ pubkey_fuzz.o $(SK_NULL_OBJS) $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

sig_fuzz: sig_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ sig_fuzz.o $(SK_NULL_OBJS) $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

authopt_fuzz: authopt_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ authopt_fuzz.o $(SK_NULL_OBJS) ../../../auth-options.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

authkeys_fuzz: authkeys_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ authkeys_fuzz.o $(SK_NULL_OBJS) ../../../auth-options.o ../../../auth2-pubkeyfile.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

sshsig_fuzz: sshsig_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ sshsig_fuzz.o $(SK_NULL_OBJS) ../../../sshsig.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

sshsigopt_fuzz: sshsigopt_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ sshsigopt_fuzz.o $(SK_NULL_OBJS) ../../../sshsig.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

privkey_fuzz: privkey_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ privkey_fuzz.o $(SK_NULL_OBJS) $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

kex_fuzz: kex_fuzz.o $(SK_NULL_OBJS) $(COMMON_DEPS)
	$(CXX) -o $@ kex_fuzz.o $(SK_NULL_OBJS) $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

agent_fuzz: agent_fuzz.o agent_fuzz_helper.o sk-dummy.o ../../../ssh-sk.o $(COMMON_DEPS)
	$(CXX) -o $@ agent_fuzz.o agent_fuzz_helper.o sk-dummy.o ../../../ssh-sk.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS) -lz

agent_fuzz_helper.o: agent_fuzz_helper.c ../../../ssh-agent.c

sk-dummy.o: ../sk-dummy/sk-dummy.c
	$(CC) $(CFLAGS) -c -o $@ ../sk-dummy/sk-dummy.c -DSK_DUMMY_INTEGRATE=1 $(LDFLAGS) $(FUZZ_FLAGS)

mkcorpus_sntrup761: mkcorpus_sntrup761.o
	$(CC) -o $@ mkcorpus_sntrup761.o $(LDFLAGS) -lcrypto

sntrup761_dec_fuzz: sntrup761_dec_fuzz.o
	$(CXX) -o $@ sntrup761_dec_fuzz.o $(LDFLAGS) $(FUZZ_FLAGS) $(FUZZ_LIBS) -lcrypto

sntrup761_enc_fuzz: sntrup761_enc_fuzz.o
	$(CXX) -o $@ sntrup761_enc_fuzz.o $(LDFLAGS) $(FUZZ_FLAGS) $(FUZZ_LIBS) -lcrypto

# HPN-SSH SFTP extension fuzzers (not present upstream).
# sftp_fs_info_fuzz: pure sshbuf parser, only needs libssh + compat.
sftp_fs_info_fuzz: sftp_fs_info_fuzz.o $(COMMON_DEPS)
	$(CXX) -o $@ sftp_fs_info_fuzz.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

# sftp_tar_parser_fuzz: the in-tree USTAR parser the product actually
# runs (replaces the libarchive reader the stale sftp_bundle_extract_fuzz
# still targets).  Links sftp-hpn-tar.o directly - it is not in libssh.a
# but its only deps (xmalloc/log/sshbuf) are.  Build ../../../sftp-hpn-tar.o
# with the same sanitizer opts as libssh (see the top-of-file NB).
sftp_tar_parser_fuzz: sftp_tar_parser_fuzz.o ../../../sftp-hpn-tar.o $(COMMON_DEPS)
	$(CXX) -o $@ sftp_tar_parser_fuzz.o ../../../sftp-hpn-tar.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

# sftp_bundle_fetch_parse_fuzz: pure sshbuf request parser, only needs
# libssh + compat.
sftp_bundle_fetch_parse_fuzz: sftp_bundle_fetch_parse_fuzz.o $(COMMON_DEPS)
	$(CXX) -o $@ sftp_bundle_fetch_parse_fuzz.o $(LDFLAGS) $(FUZZ_FLAGS) $(LIBS)

# Corpus generators - built with plain CFLAGS (no sanitizer/fuzzer).
# These are dev tools, not fuzz targets; they emit binary seed files
# into the matching ./*_corpus/ directory.
mkcorpus_sftp_fs_info: mkcorpus_sftp_fs_info.c
	$(CC) $(CFLAGS) -o $@ mkcorpus_sftp_fs_info.c

# Drives the in-tree writer to emit matched-pair tar seeds; links the
# codec object (built with plain CFLAGS is fine - this is not a fuzz
# target).
mkcorpus_sftp_tar_parser: mkcorpus_sftp_tar_parser.c ../../../sftp-hpn-tar.o
	$(CC) $(CFLAGS) -o $@ mkcorpus_sftp_tar_parser.c ../../../sftp-hpn-tar.o $(LDFLAGS) -lssh -lopenbsd-compat -lcrypto

mkcorpus_sftp_bundle_fetch_parse: mkcorpus_sftp_bundle_fetch_parse.c
	$(CC) $(CFLAGS) -o $@ mkcorpus_sftp_bundle_fetch_parse.c

# Build seeds for the HPN-SSH SFTP-extension fuzzers.  Run this once
# before invoking the corresponding ./*_fuzz binaries.
corpus: mkcorpus_sftp_fs_info mkcorpus_sftp_tar_parser \
	mkcorpus_sftp_bundle_fetch_parse
	./mkcorpus_sftp_fs_info
	./mkcorpus_sftp_tar_parser
	./mkcorpus_sftp_bundle_fetch_parse

.PHONY: corpus

clean:
	-rm -f *.o $(TARGETS)

cleandir: clean

