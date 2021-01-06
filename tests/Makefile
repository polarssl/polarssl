
# To compile on SunOS: add "-lsocket -lnsl" to LDFLAGS
# To compile with PKCS11: add "-lpkcs11-helper" to LDFLAGS

CFLAGS	?= -O2
WARNING_CFLAGS ?= -Wall -Wextra
LDFLAGS ?=

# Include public header files from ../include, test-specific header files
# from ./include, and private header files (used by some invasive tests)
# from ../library.
LOCAL_CFLAGS = $(WARNING_CFLAGS) -I./include -I../include -I../library -D_FILE_OFFSET_BITS=64
LOCAL_LDFLAGS = -L../library			\
		-lmbedtls$(SHARED_SUFFIX)	\
		-lmbedx509$(SHARED_SUFFIX)	\
		-lmbedcrypto$(SHARED_SUFFIX)

include ../3rdparty/Makefile.inc
LOCAL_CFLAGS+=$(THIRDPARTY_INCLUDES)

# Enable definition of various functions used throughout the testsuite
# (gethostname, strdup, fileno...) even when compiling with -std=c99. Harmless
# on non-POSIX platforms.
LOCAL_CFLAGS += -D_POSIX_C_SOURCE=200809L

ifndef SHARED
MBEDLIBS=../library/libmbedcrypto.a ../library/libmbedx509.a ../library/libmbedtls.a
else
MBEDLIBS=../library/libmbedcrypto.$(DLEXT) ../library/libmbedx509.$(DLEXT) ../library/libmbedtls.$(DLEXT)
endif

ifdef DEBUG
LOCAL_CFLAGS += -g3
endif

ifdef RECORD_PSA_STATUS_COVERAGE_LOG
LOCAL_CFLAGS += -Werror -DRECORD_PSA_STATUS_COVERAGE_LOG
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

# Zlib shared library extensions:
ifdef ZLIB
LOCAL_LDFLAGS += -lz
endif

# A test application is built for each suites/test_suite_*.data file.
# Application name is same as .data file's base name and can be
# constructed by stripping path 'suites/' and extension .data.
APPS = $(basename $(subst suites/,,$(wildcard suites/test_suite_*.data)))

# Construct executable name by adding OS specific suffix $(EXEXT).
BINARIES := $(addsuffix $(EXEXT),$(APPS))

.SILENT:

.PHONY: all check test clean

all: $(BINARIES)

$(MBEDLIBS):
	$(MAKE) -C ../library

MBEDTLS_TEST_OBJS=$(patsubst %.c,%.o,$(wildcard src/*.c src/drivers/*.c))

mbedtls_test: $(MBEDTLS_TEST_OBJS)

TEST_HELPERS_DEPS = $(wildcard include/test/*.h)
TEST_DRIVERS_DEPS = $(TEST_HELPERS_DEPS) $(wildcard include/test/drivers/*.h)

ifdef LOOPBACK_DRIVER
# The loopback test drivers call a copy of the library code with modified
# names for macros, types, functions and other identifiers so that the test
# driver code can reference names both from the library that calls it and
# from the library that it calls at the same time.

# The copy of the library code is in tests/include/libcopy1/*/*.h
# and tests/src/libcopy1/*.[hc].

# Perl code that is executed to transform each original line from a library
# source file into the corresponding line in the copy of the library.
# Add a libcopy1_/LIBCOPY1_ to mbedtls_xxx and psa_xxx identifiers.
# Change include directives to point to the copy of the library.
define libcopy_rewrite :=
	s!^(\s*#\s*include\s*[\"<])(mbedtls|psa)/!$${1}libcopy1/$${2}/!; \
	next if /^\s*#\s*include/; \
	s/\b(?=MBEDTLS_|PSA_)/LIBCOPY1_/g; \
	s/\b(?=mbedtls_|psa_)/libcopy1_/g;
endef

libcopy1_headers = $(subst ../include,include/libcopy1,$(wildcard ../include/*/*.h))
$(filter-out %/mbedtls/config.h,$(libcopy1_headers)): \
		include/libcopy1/%.h: ../include/%.h
	mkdir -p $(@D)
	perl -pe '$(libcopy_rewrite)' <$< >$@
# mbedtls/config.h gets special treatment: make it the full crypto config,
# except no saved NV seed so that there's no need to set up a seedfile.
include/libcopy1/mbedtls/config.h: include/libcopy1/mbedtls/config.original-names.h
	mkdir -p $(@D)
	perl -pe '$(libcopy_rewrite)' <$< >$@
include/libcopy1/mbedtls/config.original-names.h:
	mkdir -p $(@D)
	../scripts/config.py -f ../include/mbedtls/config.h -w $@ crypto_full
	../scripts/config.py -f $@ unset MBEDTLS_ENTROPY_NV_SEED
	../scripts/config.py -f $@ unset MBEDTLS_PLATFORM_NV_SEED_ALT

libcopy1_sources = \
	$(subst ..,src/libcopy1, \
		$(wildcard ../library/*.[ch]))
$(libcopy1_sources): src/libcopy1/library/%: ../library/%
	mkdir -p $(@D)
	perl -pe '$(libcopy_rewrite)' <$< >$@

libcopy1_modules = $(filter %.c,$(libcopy1_sources))
libcopy1_objects = $(libcopy1_modules:.c=.o)
$(libcopy1_objects): $(filter %.h,$(libcopy1_sources)) $(libcopy1_headers)
$(libcopy1_objects): %.o: %.c
	$(CC) -g3 -D_FILE_OFFSET_BITS=64 -I include $(CFLAGS) -o $@ -c $<

LOCAL_CFLAGS += -DPSA_CRYPTO_DRIVER_TEST_LOOPBACK
TEST_DRIVERS_DEPS += $(libcopy1_headers)
MBEDTLS_TEST_OBJS += $(libcopy1_objects)
endif #ifdef LOOPBACK_DRIVER

# Rule to compile common test C files in src folder
src/%.o : src/%.c $(TEST_HELPERS_DEPS)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -o $@ -c $<

src/drivers/%.o : src/drivers/%.c $(TEST_DRIVERS_DEPS)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) -o $@ -c $<

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


$(BINARIES): %$(EXEXT): %.c $(MBEDLIBS) $(MBEDTLS_TEST_OBJS)
	echo "  CC    $<"
	$(CC) $(LOCAL_CFLAGS) $(CFLAGS) $< $(MBEDTLS_TEST_OBJS) $(LOCAL_LDFLAGS) $(LDFLAGS) -o $@

# Some test suites require additional header files.
$(filter test_suite_psa_crypto%, $(BINARIES)): include/test/psa_crypto_helpers.h
$(addprefix embedded_,$(filter test_suite_psa_crypto%, $(APPS))): embedded_%: TESTS/mbedtls/%/psa_crypto_helpers.h
$(filter test_suite_psa_%, $(BINARIES)): include/test/psa_helpers.h
$(addprefix embedded_,$(filter test_suite_psa_%, $(APPS))): embedded_%: TESTS/mbedtls/%/psa_helpers.h

clean:
ifndef WINDOWS
	rm -rf $(BINARIES) *.c *.datax TESTS
	rm -f src/*.o src/drivers/*.o src/libmbed*
	rm -rf include/libcopy1 src/libcopy1
else
	if exist *.c del /Q /F *.c
	if exist *.exe del /Q /F *.exe
	if exist *.datax del /Q /F *.datax
	if exist src/*.o del /Q /F src/*.o
	if exist src/drivers/*.o del /Q /F src/drivers/*.o
	if exist src/libmbed* del /Q /F src/libmed*
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

define copy_header_to_target
TESTS/mbedtls/$(1)/$(2): include/test/$(2)
	echo "  Copy ./$$@"
ifndef WINDOWS
	mkdir -p $$(@D)
	cp $$< $$@
else
	mkdir $$(@D)
	copy $$< $$@
endif

endef
$(foreach app, $(APPS), $(foreach file, $(notdir $(wildcard include/test/*.h)), \
	$(eval $(call copy_header_to_target,$(app),$(file)))))

ifdef RECORD_PSA_STATUS_COVERAGE_LOG
$(BINARIES): include/test/instrument_record_status.h
include/test/instrument_record_status.h: ../include/psa/crypto.h Makefile
	sed <../include/psa/crypto.h >$@ -n 's/^psa_status_t \([A-Za-z0-9_]*\)(.*/#define \1(...) RECORD_STATUS("\1", \1(__VA_ARGS__))/p'
endif
