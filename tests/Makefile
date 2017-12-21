
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile with PKCS11: add "-lpkcs11-helper" to LDFLAGS

CFLAGS	?= -O2
WARNING_CFLAGS ?= -Wall -W -Wdeclaration-after-statement -Wno-unused-function -Wno-unused-value
LDFLAGS ?=

LOCAL_CFLAGS = $(WARNING_CFLAGS) -I../include -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = -L../library 			\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

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
else
DLEXT=so
EXEXT=
SHARED_SUFFIX=
endif

# Zlib shared library extensions:
ifdef ZLIB
LOCAL_LDFLAGS += -lz
endif

APPS =	test_suite_aes.ecb$(EXEXT)	test_suite_aes.cbc$(EXEXT)	\
	test_suite_aes.cfb$(EXEXT)	test_suite_aes.rest$(EXEXT)	\
	test_suite_arc4$(EXEXT)		test_suite_asn1write$(EXEXT)	\
	test_suite_base64$(EXEXT)	test_suite_blowfish$(EXEXT)	\
	test_suite_camellia$(EXEXT)	test_suite_ccm$(EXEXT)		\
	test_suite_cmac$(EXEXT)						\
	test_suite_cipher.aes$(EXEXT)					\
	test_suite_cipher.arc4$(EXEXT)	test_suite_cipher.ccm$(EXEXT)	\
	test_suite_cipher.gcm$(EXEXT)					\
	test_suite_cipher.blowfish$(EXEXT)				\
	test_suite_cipher.camellia$(EXEXT)				\
	test_suite_cipher.des$(EXEXT)	test_suite_cipher.null$(EXEXT)	\
	test_suite_cipher.padding$(EXEXT)				\
	test_suite_ctr_drbg$(EXEXT)	test_suite_debug$(EXEXT)	\
	test_suite_des$(EXEXT)		test_suite_dhm$(EXEXT)		\
	test_suite_ecdh$(EXEXT)		test_suite_ecdsa$(EXEXT)	\
	test_suite_ecjpake$(EXEXT)	test_suite_ecp$(EXEXT)		\
	test_suite_error$(EXEXT)	test_suite_entropy$(EXEXT)	\
	test_suite_gcm.aes128_de$(EXEXT)				\
	test_suite_gcm.aes192_de$(EXEXT)				\
	test_suite_gcm.aes256_de$(EXEXT)				\
	test_suite_gcm.aes128_en$(EXEXT)				\
	test_suite_gcm.aes192_en$(EXEXT)				\
	test_suite_gcm.aes256_en$(EXEXT)				\
	test_suite_gcm.camellia$(EXEXT)					\
	test_suite_hmac_drbg.misc$(EXEXT)				\
	test_suite_hmac_drbg.no_reseed$(EXEXT)				\
	test_suite_hmac_drbg.nopr$(EXEXT)				\
	test_suite_hmac_drbg.pr$(EXEXT)					\
	test_suite_md$(EXEXT)		test_suite_mdx$(EXEXT)		\
	test_suite_memory_buffer_alloc$(EXEXT)				\
	test_suite_mpi$(EXEXT)						\
	test_suite_pem$(EXEXT)			test_suite_pkcs1_v15$(EXEXT)	\
	test_suite_pkcs1_v21$(EXEXT)	test_suite_pkcs5$(EXEXT)	\
	test_suite_pkparse$(EXEXT)	test_suite_pkwrite$(EXEXT)	\
	test_suite_pk$(EXEXT)						\
	test_suite_rsa$(EXEXT)		test_suite_shax$(EXEXT)		\
	test_suite_ssl$(EXEXT)		test_suite_timing$(EXEXT)			\
	test_suite_x509parse$(EXEXT)	test_suite_x509write$(EXEXT)	\
	test_suite_xtea$(EXEXT)		test_suite_version$(EXEXT)

.SILENT:

.PHONY: all all_c check clean dynamic_libraries test

all: $(APPS)
all_c: $(APPS:$(EXEXT)=.c)

ifndef SHARED
STATIC_LIBRARIES = ../library/libmbedcrypto.a ../library/libmbedx509.a ../library/libmbedtls.a
DYNAMIC_LIBRARIES =
$(STATIC_LIBRARIES):
	$(MAKE) -C ../library
else
STATIC_LIBRARIES =
DYNAMIC_LIBRARIES = ../library/libmbedcrypto.$(DLEXT) ../library/libmbedx509.$(DLEXT) ../library/libmbedtls.$(DLEXT)
$(DYNAMIC_LIBRARIES):
	$(MAKE) -C ../library
endif
dynamic_libraries: $(DYNAMIC_LIBRARIES)

common_source_deps = scripts/generate_code.pl \
	suites/helpers.function suites/main_test.function

# Each .c file depends on a .function file and a .data file. There are two
# cases:
# * Straight: FOO.c: suites/FOO.function suites/FOO.data
# * Split: FOO.BAR.c: suites/FOO.function suites/FOO.BAR.data
# The macro c_function_rule provides a template which builds the dependency
# on the .function file from an input of the form "suites/FOO.data" or
# "suites/FOO.BAR.data". The foreach call below expands this template for
# all the .data files in the "suites" directory. The dependency on the
# .data file is expressed directly by the pattern rule for %.c.
define c_function_rule
$$(basename $$(notdir $(1))).c: $$(basename $$(basename $(1))).function

endef
$(foreach f, $(wildcard suites/test_suite_*.data), \
 $(eval $(call c_function_rule,$(f))))

# invoke perl explicitly for the sake of mingw32-make
%.c : suites/%.data $(common_source_deps)
	echo "  Gen   $@"
	perl scripts/generate_code.pl suites $(basename $(*)) $*

%$(EXEXT): %.c $(STATIC_LIBRARIES)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $< $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

clean:
ifndef WINDOWS
	rm -f $(APPS) *.c
else
	del /Q /F *.c *.exe
endif

check: dynamic_libraries $(APPS)
	perl scripts/run-test-suites.pl

test: check

include .depend
