Alternative implementations of Mbed TLS functionality
=====================================================

This document describes how parts of the Mbed TLS functionality can be replaced at compile time to integrate the library on a platform.

This document is an overview. It is not exhaustive. Please consult the documentation of individual modules and read the library header files for more details.

## Platform integration

Mbed TLS works out of the box on Unix/Linux/POSIX-like systems and on Windows. On embedded platforms, you may need to customize some aspects of how Mbed TLS interacts with the underlying platform. This section discusses the main areas that can be configured.

The platform module (`include/mbedtls/platform.h`) controls how Mbed TLS accesses standard library features such as memory management (`calloc`, `free`), `printf`, `exit`. You can define custom functions instead of the ones from the C standard library through `MBEDTLS_PLATFORM_XXX` options in the configuration file. Many options have two mechanisms: either define `MBEDTLS_PLATFORM_XXX_MACRO` to the name of a function to call instead of the standard function `xxx`, or define `MBEDTLS_PLATFORM_XXX_ALT` and [register an alternative implementation during the platform setup](#alternative-implementations-of-platform-functions).

The storage of the non-volatile seed for random generation, enabled with `MBEDTLS_ENTROPY_NV_SEED`, is also controlled via the platform module.

For timing functions, you can [declare an alternative implementation of the timing module](#module-alternative-implementations).

On multithreaded platforms, [declare an alternative implementation of the threading module](#module-alternative-implementations).

To configure entropy sources (hardware random generators), see the `MBEDTLS_ENTROPY_XXX` options in the configuration file.

For networking, the `net_sockets` module does not currently support alternative implementations. If this module does not work on your platform, disable `MBEDTLS_NET_C` and use custom functions for TLS.

If your platform has a cryptographic accelerator, you can use it via a [PSA driver](#psa-cryptography-drivers) or an [declare an alternative implementation of the corresponding module(s)](#module-alternative-implementations) or [specific functions](#function-alternative-implementations).

## PSA cryptography drivers

On platforms where a hardware cryptographic engine is present, you can implement a driver for this engine in the PSA interface. Drivers are supported for cryptographic operations with transparent keys (keys available in cleartext), for cryptographic operations with opaque keys (keys that are only available inside the cryptographic engine), and for random generation. Calls to `psa_xxx` functions that perform cryptographic operations are directed to drivers instead of the built-in code as applicable. See the [PSA cryptography driver interface specification](docs/proposed/psa-driver-interface.md), the [Mbed TLS PSA driver developer guide](docs/proposed/psa-driver-developer-guide.md) and the [Mbed TLS PSA driver integration guide](docs/proposed/psa-driver-integration-guide.md) for more information.

As of Mbed TLS 3.0, this interface is still experimental and subject to change, and not all operations support drivers yet. The configuration option `MBEDTLS_USE_PSA_CRYPTO` causes parts of the `mbedtls_xxx` API to use PSA crypto and therefore to support drivers, however it is not yet compatible with all drivers.

## Module alternative implementations

You can replace the code of some modules of Mbed TLS at compile time by a custom implementation. This is possible for low-level cryptography modules (symmetric algorithms, DHM, RSA, ECP, ECJPAKE) and for some platform-related modules (threading, timing). Such custom implementations are called “alternative implementations”, or “ALT implementations” for short.

The general principle of an alternative implementation is:
* Enable `MBEDTLS_XXX_ALT` in the compile-time configuration where XXX is the module name. For example, `MBEDTLS_AES_ALT` for an implementation of the AES module. This is in addition to enabling `MBEDTLS_XXX_C`.
* Create a header file `xxx_alt.h` that defines the context type(s) used by the module. For example, `mbedtls_aes_context` for AES.
* Implement all the functions from the module, i.e. the functions declared in `include/mbedtls/xxx.h`.

See https://tls.mbed.org/kb/development/hw_acc_guidelines for a more detailed guide.

## Function alternative implementations

In some cases, it is possible to replace a single function or a small set of functions instead of [providing an alternative implementation of the whole module](#module-alternative-implementations).

### Alternative implementations of cryptographic functions

Options to replace individual functions of cryptographic modules generally have a name obtained by upper-casing the function name and appending `_ALT`. If the function name contains `_internal`, `_ext` or `_ret`, this is removed in the `_ALT` symbol. When the corresponding option is enabled, the built-in implementation of the function will not be compiled, and you must provide an alternative implementation at link time.

For example, enable `MBEDTLS_AES_ENCRYPT_ALT` at compile time and provide your own implementation of `mbedtls_aes_encrypt()` to provide an accelerated implementation of AES encryption that is compatible with the built-in key schedule. If you wish to implement key schedule differently, you can also enable `MBEDTLS_AES_SETKEY_ENC_ALT` and implement `mbedtls_aes_setkey_enc()`.

Another example: enable `MBEDTLS_SHA256_PROCESS_ALT` and implement `mbedtls_internal_sha256_process()` to provide an accelerated implementation of SHA-256 and SHA-224.

Note that since alternative implementations of individual functions cooperate with the built-in implementation of other functions, you must use the same layout for context objects as the built-in implementation. If you want to use different context types, you need to [provide an alternative implementation of the whole module](#module-alternative-implementations).

### Alternative implementations of platform functions

Several platform functions can be reconfigured dynamically by following the process described here. To reconfigure how Mbed TLS calls the standard library function `xxx()`:

* Define the symbol `MBEDTLS_PLATFORM_XXX_ALT` at compile time.
* During the initialization of your application, set the global variable `mbedtls_xxx` to an alternative implementation of `xxx()`.

Merely enabling `MBEDTLS_PLATFORM_XXX_ALT` does not change the behavior: by default, `mbedtls_xxx` points to the standard function `xxx`.

Note that there are variations on the naming pattern. Consult the documentation of individual configuration options and of the platform module for details.