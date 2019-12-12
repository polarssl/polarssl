
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile with PKCS11: add "-lpkcs11-helper" to LDFLAGS

CFLAGS	?= -O2
WARNING_CFLAGS ?= -Wall -Wextra
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = -L../library			\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

LOCAL_LDFLAGS += -L../crypto/library
LOCAL_CFLAGS += -I../crypto/include
CRYPTO := ../crypto/library/

INCLUDING_FROM_MBEDTLS:=1
include ../crypto/3rdparty/Makefile.inc
LOCAL_CFLAGS += $(patsubst -I../3rdparty/%, -I../crypto/3rdparty/%, $(THIRDPARTY_INCLUDES))

# Enable definition of various functions used throughout the testsuite
# (gethostname, strdup, fileno...) even when compiling with -std=c99. Harmless
# on non-POSIX platforms.
LOCAL_CFLAGS += -D_POSIX_C_SOURCE=200809L

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

# if we're running on Windows, build for Windows
ifdef WINDOWS
WINDOWS_BUILD=1
endif

ifdef WINDOWS_BUILD
DLEXT=dll
EXEXT=.exe
LOCAL_LDFLAGS += -lws2_32
ifdef SHARED
SHARED_SUFFIX=.$(DLEXT)
endif
PYTHON ?= python
else
DLEXT ?= so
EXEXT=
SHARED_SUFFIX=
# python2 for POSIX since FreeBSD has only python2 as default.
PYTHON ?= python2
endif

ifndef SHARED
DEP=$(CRYPTO)libmbedcrypto.a ../library/libmbedx509.a ../library/libmbedtls.a
else
DEP=$(CRYPTO)libmbedcrypto.$(DLEXT) ../library/libmbedx509.$(DLEXT) ../library/libmbedtls.$(DLEXT)
endif

# Zlib shared library extensions:
ifdef ZLIB
LOCAL_LDFLAGS += -lz
endif

# Pthread shared library extension
ifdef PTHREAD
LOCAL_LDFLAGS += -lpthread
endif

# A test application is built for each suites/test_suite_*.data file.
# Application name is same as .data file's base name and can be
# constructed by stripping path 'suites/' and extension .data.
APPS = $(basename $(subst suites/,,$(wildcard suites/test_suite_*.data)))

APPS := $(filter-out \
		test_suite_aes.% \
		test_suite_arc4 \
		test_suite_aria \
		test_suite_asn1write \
		test_suite_base64 \
		test_suite_blowfish \
		test_suite_camellia \
		test_suite_ccm \
		test_suite_chacha20 \
		test_suite_chachapoly \
		test_suite_cipher.% \
		test_suite_cmac \
		test_suite_ctr_drbg \
		test_suite_des \
		test_suite_dhm \
		test_suite_ecdh \
		test_suite_ecdsa \
		test_suite_ecjpake \
		test_suite_ecp \
		test_suite_entropy \
		test_suite_error \
		test_suite_gcm.% \
		test_suite_hkdf \
		test_suite_hmac_drbg.% \
		test_suite_md \
		test_suite_mdx \
		test_suite_memory_buffer_alloc \
		test_suite_mpi \
		test_suite_nist_kw \
		test_suite_oid \
		test_suite_pem \
		test_suite_pk \
		test_suite_pkcs1_v15 \
		test_suite_pkcs1_v21 \
		test_suite_pkcs5 \
		test_suite_pkparse \
		test_suite_pkwrite \
		test_suite_poly1305 \
		test_suite_rsa \
		test_suite_shax \
		test_suite_timing \
		test_suite_xtea \
		,$(APPS))

ifndef PTHREAD
APPS := $(filter-out test_suite_x509parse_pthread, $(APPS))
endif

# Construct executable name by adding OS specific suffix $(EXEXT).
BINARIES := $(addsuffix $(EXEXT),$(APPS))

.SILENT:

.PHONY: all check test clean

all: $(BINARIES)

$(DEP):
	$(MAKE) -C ../library

C_FILES := $(addsuffix .c,$(APPS))

# Wildcard target for test code generation:
# A .c file is generated for each .data file in the suites/ directory. Each .c
# file depends on a .data and .function file from suites/ directory. Following
# nameing convention is followed:
#
#     C file        |        Depends on
#-----------------------------------------------------------------------------
#  foo.c            | suites/foo.function suites/foo.data
#  foo.bar.c        | suites/foo.function suites/foo.bar.data
#
# Note above that .c and .data files have same base name.
# However, corresponding .function file's base name is the word before first
# dot in .c file's base name.
#
.SECONDEXPANSION:
%.c: suites/$$(firstword $$(subst ., ,$$*)).function suites/%.data scripts/generate_test_code.py suites/helpers.function suites/main_test.function suites/host_test.function
	echo "  Gen   $@"
	$(PYTHON) scripts/generate_test_code.py -f suites/$(firstword $(subst ., ,$*)).function \
		-d suites/$*.data \
		-t suites/main_test.function \
		-p suites/host_test.function \
		-s suites  \
		--helpers-file suites/helpers.function \
		-o .


$(BINARIES): %$(EXEXT): %.c $(DEP)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $<	$(LOCAL_LDFLAGS) $(LDFLAGS) -o $@


clean:
ifndef WINDOWS
	rm -rf $(BINARIES) *.c *.datax TESTS
else
	if exist *.c del /Q /F *.c
	if exist *.exe del /Q /F *.exe
	if exist *.datax del /Q /F *.datax
ifneq ($(wildcard TESTS/.*),)
	rmdir /Q /S TESTS
endif
endif

# Test suites caught by SKIP_TEST_SUITES are built but not executed.
check: $(BINARIES)
	perl scripts/run-test-suites.pl --skip=$(SKIP_TEST_SUITES)

test: check

# Create separate targets for generating embedded tests.
EMBEDDED_TESTS := $(addprefix embedded_,$(APPS))

# Generate test code for target.

.SECONDEXPANSION:
$(EMBEDDED_TESTS): embedded_%: suites/$$(firstword $$(subst ., ,$$*)).function suites/%.data scripts/generate_test_code.py suites/helpers.function suites/main_test.function suites/target_test.function
	echo "  Gen  ./TESTS/mbedtls/$*/$*.c"
	$(PYTHON) scripts/generate_test_code.py -f suites/$(firstword $(subst ., ,$*)).function \
		-d suites/$*.data \
		-t suites/main_test.function \
		-p suites/target_test.function \
		-s suites  \
		--helpers-file suites/helpers.function \
		-o ./TESTS/mbedtls/$*

generate-target-tests: $(EMBEDDED_TESTS)
