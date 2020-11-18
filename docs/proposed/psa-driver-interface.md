PSA Cryptoprocessor Driver Interface
====================================

This document describes an interface for cryptoprocessor drivers in the PSA cryptography API. This interface complements the [PSA Cryptography API specification](https://armmbed.github.io/mbed-crypto/psa/#application-programming-interface), which describes the interface between a PSA Cryptography implementation and an application.

This specification is work in progress and should be considered to be in a beta stage. There is ongoing work to implement this interface in Mbed TLS, which is the reference implementation of the PSA Cryptography API. At this stage, Arm does not expect major changes, but minor changes are expected based on experience from the first implementation and on external feedback.

Time-stamp: "2020/08/19 19:47:39 GMT"

## Introduction

### Purpose of the driver interface

The PSA Cryptography API defines an interface that allows applications to perform cryptographic operations in a uniform way regardless of how the operations are performed. Under the hood, different keys may be stored and used in different hardware or in different logical partitions, and different algorithms may involve different hardware or software components.

The driver interface allows implementations of the PSA Cryptography API to be built compositionally. An implementation of the PSA Cryptography API is composed of a **core** and zero or more **drivers**. The core handles key management, enforces key usage policies, and dispatches cryptographic operations either to the applicable driver or to built-in code.

Functions in the PSA Cryptography API invoke functions in the core. Code from the core calls drivers as described in the present document.

### Types of drivers

The PSA Cryptography driver interface supports two types of cryptoprocessors, and accordingly two types of drivers.

* **Transparent** drivers implement cryptographic operations on keys that are provided in cleartext at the beginning of each operation. They are typically used for hardware **accelerators**. When a transparent driver is available for a particular combination of parameters (cryptographic algorithm, key type and size, etc.), it is used instead of the default software implementation. Transparent drivers can also be pure software implementations that are distributed as plug-ins to a PSA Cryptography implementation (for example, an alternative implementation with different performance characteristics, or a certified implementation).
* **Opaque** drivers implement cryptographic operations on keys that can only be used inside a protected environment such as a **secure element**, a hardware security module, a smartcard, a secure enclave, etc. An opaque driver is invoked for the specific [key location](#lifetimes-and-locations) that the driver is registered for: the dispatch is based on the key's lifetime.

### Requirements

The present specification was designed to fulfill the following high-level requirements.

[Req.plugins] It is possible to combine multiple drivers from different providers into the same implementation, without any prior arrangement other than choosing certain names and values from disjoint namespaces.

[Req.compile] It is possible to compile the code of each driver and of the core separately, and link them together. A small amount of glue code may need to be compiled once the list of drivers is available.

[Req.types] Support drivers for the following types of hardware: accelerators that operate on keys in cleartext; cryptoprocessors that can wrap keys with a built-in keys but not store user keys; and cryptoprocessors that store key material.

[Req.portable] The interface between drivers and the core does not involve any platform-specific consideration. Driver calls are simple C function calls. Interactions with platform-specific hardware happen only inside the driver (and in fact a driver need not involve any hardware at all).

[Req.location] Applications can tell which location values correspond to which secure element drivers.

[Req.fallback] Accelerator drivers can specify that they do not fully support a cryptographic mechanism and that a fallback to core code may be necessary. Conversely, if an accelerator fully supports cryptographic mechanism, the core must be able to omit code for this mechanism.

[Req.mechanisms] Drivers can specify which mechanisms they support. A driver's code will not be invoked for cryptographic mechanisms that it does not support.

## Overview of drivers

### Deliverables for a driver

To write a driver, you need to implement some functions with C linkage, and to declare these functions in a **driver description file**. The driver description file declares which functions the driver implements and what cryptographic mechanisms they support. If the driver description references custom types, macros or constants, you also need to provide C header files defining those elements.

The concrete syntax for a driver description file is JSON. The structure of this JSON file is specified in the section [“Driver description syntax”](#driver-description-syntax).

A driver therefore consists of:

* A driver description file (in JSON format).
* C header files defining the types required by the driver description. The names of these header files are declared in the driver description file.
* An object file compiled for the target platform defining the entry point functions specified by the driver description. Implementations may allow drivers to be provided as source files and compiled with the core instead of being pre-compiled.

How to provide the driver description file, the C header files and the object code is implementation-dependent.

### Driver description syntax

The concrete syntax for a driver description file is JSON.

#### Driver description list

PSA Cryptography core implementations should support multiple drivers. The driver description files are passed to the implementation as an ordered list in an unspecified manner. This may be, for example, a list of file names passed on a command line, or a JSON list whose elements are individual driver descriptions.

#### Driver description top-level element

A driver description is a JSON object containing the following properties:

* `"prefix"` (mandatory, string). This must be a valid prefix for a C identifier. All the types and functions provided by the driver have a name that starts with this prefix unless overridden with a `"name"` element in the applicable capability as described below.
* `"type"` (mandatory, string). One of `"transparent"` or `"opaque"`.
* `"headers"` (optional, array of strings). A list of header files. These header files must define the types, macros and constants referenced by the driver description. They may declare the entry point functions, but this is not required. They may include other PSA headers and standard headers of the platform. Whether they may include other headers is implementation-specific. If omitted, the list of headers is empty. The header files must be present at the specified location relative to a directory on the compiler's include path when compiling glue code between the core and the drivers.
* `"capabilities"` (mandatory, array of [capabilities](#driver-description-capability)).
A list of **capabilities**. Each capability describes a family of functions that the driver implements for a certain class of cryptographic mechanisms.
* `"key_context"` (not permitted for transparent drivers, mandatory for opaque drivers): information about the [representation of keys](#key-format-for-opaque-drivers).
* `"persistent_state_size"` (not permitted for transparent drivers, optional for opaque drivers, integer or string). The size in bytes of the [persistent state of the driver](#opaque-driver-persistent-state). This may be either a non-negative integer or a C constant expression of type `size_t`.
* `"location"` (not permitted for transparent drivers, optional for opaque drivers, integer or string). The [location value](#lifetimes-and-locations) for which this driver is invoked. In other words, this determines the lifetimes for which the driver is invoked. This may be either a non-negative integer or a C constant expression of type `psa_key_location_t`.

### Driver description capability

#### Capability syntax

A capability declares a family of functions that the driver implements for a certain class of cryptographic mechanisms. The capability specifies which key types and algorithms are covered and the names of the types and functions that implement it.

A capability is a JSON object containing the following properties:

* `"entry_points"` (mandatory, list of strings). Each element is the name of a [driver entry point](#driver-entry-points) or driver entry point family. An entry point is a function defined by the driver. If specified, the core will invoke this capability of the driver only when performing one of the specified operations. The driver must implement all the specified entry points, as well as the types if applicable.
* `"algorithms"` (optional, list of strings). Each element is an [algorithm specification](#algorithm-specifications). If specified, the core will invoke this capability of the driver only when performing one of the specified algorithms. If omitted, the core will invoke this capability for all applicable algorithms.
* `"key_types"` (optional, list of strings). Each element is a [key type specification](#key-type-specifications). If specified, the core will invoke this capability of the driver only for operations involving a key with one of the specified key types. If omitted, the core will invoke this capability of the driver for all applicable key types.
* `"key_sizes"` (optional, list of integers). If specified, the core will invoke this capability of the driver only for operations involving a key with one of the specified key sizes. If omitted, the core will invoke this capability of the driver for all applicable key sizes. Key sizes are expressed in bits.
* `"names"` (optional, object). A mapping from entry point names described by the `"entry_points"` property, to the name of the C function in the driver that implements the corresponding function. If a function is not listed here, name of the driver function that implements it is the driver's prefix followed by an underscore (`_`) followed by the function name. If this property is omitted, it is equivalent to an empty object (so each entry point *suffix* is implemented by a function called *prefix*`_`*suffix*).
* `"fallback"` (optional for transparent drivers, not permitted for opaque drivers, boolean). If present and true, the driver may return `PSA_ERROR_NOT_SUPPORTED`, in which case the core should call another driver or use built-in code to perform this operation. If absent or false, the driver is expected to fully support the mechanisms described by this capability. See the section “[Fallback](#fallback)” for more information.

#### Capability semantics

When the PSA Cryptography implementation performs a cryptographic mechanism, it invokes available driver entry points as described in the section [“Driver entry points”](#driver-entry-points).

A driver is considered available for a cryptographic mechanism that invokes a given entry point if all of the following conditions are met:

* The driver specification includes a capability whose `"entry_points"` list either includes the entry point or includes an entry point family that includes the entry point.
* If the mechanism involves an algorithm:
    * either the capability does not have an `"algorithms"` property;
    * or the value of the capability's `"algorithms"` property includes an [algorithm specification](#algorithm-specifications) that matches this algorithm.
* If the mechanism involves a key:
    * either the key is transparent (its location is `PSA_KEY_LOCATION_LOCAL_STORAGE`) and the driver is transparent;
    * or the key is opaque (its location is not `PSA_KEY_LOCATION_LOCAL_STORAGE`) and the driver is an opaque driver whose location is the key's location.
* If the mechanism involves a key:
    * either the capability does not have a `"key_types"` property;
    * or the value of the capability's `"key_types"` property includes a [key type specification](#key-type-specifications) that matches this algorithm.
* If the mechanism involves a key:
    * either the capability does not have a `"key_sizes"` property;
    * or the value of the capability's `"key_sizes"` property includes the key's size.

If a driver includes multiple applicable capabilities for a given combination of entry point, algorithm, key type and key size, and all the capabilities map the entry point to the same function name, the driver is considered available for this cryptographic mechanism. If a driver includes multiple applicable capabilities for a given combination of entry point, algorithm, key type and key size, and at least two of these capabilities map the entry point to the different function names, the driver specification is invalid.

If multiple transparent drivers have applicable capabilities for a given combination of entry point, algorithm, key type and key size, the first matching driver in the [specification list](#driver-description-list) is invoked. If the capability has [fallback](#fallback) enabled and the first driver returns `PSA_ERROR_NOT_SUPPORTED`, the next matching driver is invoked, and so on.

If multiple opaque drivers have the same location, the list of driver specifications is invalid.

#### Capability examples

Example 1: the following capability declares that the driver can perform deterministic ECDSA signatures (but not signature verification) using any hash algorithm and any curve that the core supports. If the prefix of this driver is `"acme"`, the function that performs the signature is called `acme_sign_hash`.
```
{
    "entry_points": ["sign_hash"],
    "algorithms": ["PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_ANY_HASH)"],
}
```

Example 2: the following capability declares that the driver can perform deterministic ECDSA signatures using SHA-256 or SHA-384 with a SECP256R1 or SECP384R1 private key (with either hash being possible in combination with either curve). If the prefix of this driver is `"acme"`, the function that performs the signature is called `acme_sign_hash`.
```
{
    "entry_points": ["sign_hash"],
    "algorithms": ["PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256)",
                   "PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384)"],
    "key_types": ["PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP_R1)"],
    "key_sizes": [256, 384]
}
```

### Algorithm and key specifications

#### Algorithm specifications

An algorithm specification is a string consisting of a `PSA_ALG_xxx` macro that specifies a cryptographic algorithm or an algorithm wildcard policy defined by the PSA Cryptography API. If the macro takes arguments, the string must have the syntax of a C macro call and each argument must be an algorithm specification or a decimal or hexadecimal literal with no suffix, depending on the expected type of argument.

Spaces are optional after commas. Whether other whitespace is permitted is implementation-specific.

Valid examples:
```
PSA_ALG_SHA_256
PSA_ALG_HMAC(PSA_ALG_SHA_256)
PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256))
PSA_ALG_RSA_PSS(PSA_ALG_ANY_HASH)
```

#### Key type specifications

An algorithm specification is a string consisting of a `PSA_KEY_TYPE_xxx` macro that specifies a key type defined by the PSA Cryptography API. If the macro takes an argument, the string must have the syntax of a C macro call and each argument must be the name of a constant of suitable type (curve or group).

The name `_` may be used instead of a curve or group to indicate that the capability concerns all curves or groups.

Valid examples:
```
PSA_KEY_TYPE_AES
PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP_R1)
PSA_KEY_TYPE_ECC_KEY_PAIR(_)
```

### Driver entry points

#### Overview of driver entry points

Drivers define functions, each of which implements an aspect of a capability of a driver, such as a cryptographic operation, a part of a cryptographic operation, or a key management action. These functions are called the **entry points** of the driver. Most driver entry points correspond to a particular function in the PSA Cryptography API. For example, if a call to `psa_sign_hash()` is dispatched to a driver, it invokes the driver's `sign_hash` function.

All driver entry points return a status of type `psa_status_t` which should use the status codes documented for PSA services in general and for PSA Cryptography in particular: `PSA_SUCCESS` indicates that the function succeeded, and `PSA_ERROR_xxx` values indicate that an error occurred.

The signature of a driver entry point generally looks like the signature of the PSA Cryptography API that it implements, with some modifications. This section gives an overview of modifications that apply to whole classes of entry points. Refer to the reference section for each entry point or entry point family for details.

* For entry points that operate on an existing key, the `psa_key_id_t` parameter is replaced by a sequence of three parameters that describe the key:
    1. `const psa_key_attributes_t *attributes`: the key attributes.
    2. `const uint8_t *key_buffer`: a key material or key context buffer.
    3. `size_t key_buffer_size`: the size of the key buffer in bytes.

    For transparent drivers, the key buffer contains the key material, in the same format as defined for `psa_export_key()` and `psa_export_public_key()` in the PSA Cryptography API. For opaque drivers, the content of the key buffer is entirely up to the driver.

* For entry points that involve a multi-part operation, the operation state type (`psa_XXX_operation_t`) is replaced by a driver-specific operation state type (*prefix*`_XXX_operation_t`).

Some entry points are grouped in families that must be implemented as a whole. If a driver supports an entry point family, it must provide all the entry points in the family.

#### General considerations on driver entry point parameters

Buffer parameters for driver entry points obey the following conventions:

* An input buffer has the type `const uint8_t *` and is immediately followed by a parameter of type `size_t` that indicates the buffer size.
* An output buffer has the type `uint8_t *` and is immediately followed by a parameter of type `size_t` that indicates the buffer size. A third parameter of type `size_t *` is provided to report the actual length of the data written in the buffer if the function succeeds.
* An in-out buffer has the type `uint8_t *` and is immediately followed by a parameter of type `size_t` that indicates the buffer size. In-out buffers are only used when the input and the output have the same length.

Buffers of size 0 may be represented with either a null pointer or a non-null pointer.

Input buffers and other input-only parameters (`const` pointers) may be in read-only memory. Overlap is possible between input buffers, and between an input buffer and an output buffer, but not between two output buffers or between a non-buffer parameter and another parameter.

#### Driver entry points for single-part cryptographic operations

The following driver entry points perform a cryptographic operation in one shot (single-part operation):

* `"hash_compute"` (transparent drivers only): calculation of a hash. Called by `psa_hash_compute()` and `psa_hash_compare()`. To verify a hash with `psa_hash_compare()`, the core calls the driver's `"hash_compute"` entry point and compares the result with the reference hash value.
* `"mac_compute"`: calculation of a MAC. Called by `psa_mac_compute()` and possibly `psa_mac_verify()`. To verify a mac with `psa_mac_verify()`, the core calls an applicable driver's `"mac_verify"` entry point if there is one, otherwise the core calls an applicable driver's `"mac_compute"` entry point and compares the result with the reference MAC value.
* `"mac_verify"`: verification of a MAC. Called by `psa_mac_verify()`. This entry point is mainly useful for drivers of secure elements that verify a MAC without revealing the correct MAC. Although transparent drivers may implement this entry point in addition to `"mac_compute"`, it is generally not useful because the core can call the `"mac_compute"` entry point and compare with the expected MAC value.
* `"cipher_encrypt"`: unauthenticated symmetric cipher encryption. Called by `psa_cipher_encrypt()`.
* `"cipher_decrypt"`: unauthenticated symmetric cipher decryption. Called by `psa_cipher_decrypt()`.
* `"aead_encrypt"`: authenticated encryption with associated data. Called by `psa_aead_encrypt()`.
* `"aead_decrypt"`: authenticated decryption with associated data. Called by `psa_aead_decrypt()`.
* `"asymmetric_encrypt"`: asymmetric encryption. Called by `psa_asymmetric_encrypt()`.
* `"asymmetric_decrypt"`: asymmetric decryption. Called by `psa_asymmetric_decrypt()`.
* `"sign_hash"`: signature of an already calculated hash. Called by `psa_sign_hash()` and possibly `psa_sign_message()`. To sign a message with `psa_sign_message()`, the core calls an applicable driver's `"sign_message"` entry point if there is one, otherwise the core calls an applicable driver's `"hash_compute"` entry point followed by an applicable driver's `"sign_hash"` entry point.
* `"verify_hash"`: verification of an already calculated hash. Called by `psa_verify_hash()` and possibly `psa_verify_message()`. To verify a message with `psa_verify_message()`, the core calls an applicable driver's `"verify_message"` entry point if there is one, otherwise the core calls an applicable driver's `"hash_compute"` entry point followed by an applicable driver's `"verify_hash"` entry point.
* `"sign_message"`: signature of a message. Called by `psa_sign_message()`.
* `"verify_message"`: verification of a message. Called by `psa_verify_message()`.
* `"key_agreement"`: key agreement without a subsequent key derivation. Called by `psa_raw_key_agreement()` and possibly `psa_key_derivation_key_agreement()`.

### Driver entry points for multi-part operations

#### General considerations on multi-part operations

The entry points that implement each step of a multi-part operation are grouped into a family. A driver that implements a multi-part operation must define all of the entry points in this family as well as a type that represents the operation context. The lifecycle of a driver operation context is similar to the lifecycle of an API operation context:

1. The core initializes operation context objects to either all-bits-zero or to logical zero (`{0}`), at its discretion.
1. The core calls the `xxx_setup` entry point for this operation family. If this fails, the core destroys the operation context object without calling any other driver entry point on it.
1. The core calls other entry points that manipulate the operation context object, respecting the constraints.
1. If any entry point fails, the core calls the driver's `xxx_abort` entry point for this operation family, then destroys the operation context object without calling any other driver entry point on it.
1. If a “finish” entry point fails, the core destroys the operation context object without calling any other driver entry point on it. The finish entry points are: *prefix*`_mac_sign_finish`, *prefix*`_mac_verify_finish`, *prefix*`_cipher_fnish`, *prefix*`_aead_finish`, *prefix*`_aead_verify`.

If a driver implements a multi-part operation but not the corresponding single-part operation, the core calls the driver's multipart operation entry points to perform the single-part operation.

#### Multi-part operation entry point family `"hash_multipart"`

This family corresponds to the calculation of a hash in multiple steps.

This family applies to transparent drivers only.

This family requires the following type and entry points:

* Type `"hash_operation_t"`: the type of a hash operation context. It must be possible to copy a hash operation context byte by byte, therefore hash operation contexts must not contain any embedded pointers (except pointers to global data that do not change after the setup step).
* `"hash_setup"`: called by `psa_hash_setup()`.
* `"hash_update"`: called by `psa_hash_update()`.
* `"hash_finish"`: called by `psa_hash_finish()` and `psa_hash_verify()`.
* `"hash_abort"`: called by all multi-part hash functions of the PSA Cryptography API.

To verify a hash with `psa_hash_verify()`, the core calls the driver's *prefix*`_hash_finish` entry point and compares the result with the reference hash value.

For example, a driver with the prefix `"acme"` that implements the `"hash_multipart"` entry point family must define the following type and entry points (assuming that the capability does not use the `"names"` property to declare different type and entry point names):

```
typedef ... acme_hash_operation_t;
psa_status_t acme_hash_setup(acme_hash_operation_t *operation,
                             psa_algorithm_t alg);
psa_status_t acme_hash_update(acme_hash_operation_t *operation,
                              const uint8_t *input,
                              size_t input_length);
psa_status_t acme_hash_finish(acme_hash_operation_t *operation,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length);
psa_status_t acme_hash_abort(acme_hash_operation_t *operation);
```

#### Operation family `"mac_multipart"`

TODO

#### Operation family `"mac_verify_multipart"`

TODO

#### Operation family `"cipher_encrypt_multipart"`

TODO

#### Operation family `"cipher_decrypt_multipart"`

TODO

#### Operation family `"aead_encrypt_multipart"`

TODO

#### Operation family `"aead_decrypt_multipart"`

TODO

#### Operation family `"key_derivation"`

This family requires the following type and entry points:

* Type `"key_derivation_operation_t"`: the type of a key derivation operation context.
* `"key_derivation_setup"`: called by `psa_key_derivation_setup()`.
* `"key_derivation_set_capacity"`: called by `psa_key_derivation_set_capacity()`. The core will always enforce the capacity, therefore this function does not need to do anything for algorithms where the output stream only depends on the effective generated length and not on the capacity.
* `"key_derivation_input_bytes"`: called by `psa_key_derivation_input_bytes()` and `psa_key_derivation_input_key()`. For transparent drivers, when processing a call to `psa_key_derivation_input_key()`, the core always calls the applicable driver's `"key_derivation_input_bytes"` entry point.
* `"key_derivation_input_key"` (opaque drivers only)
* `"key_derivation_output_bytes"`: called by `psa_key_derivation_output_bytes()`; also by `psa_key_derivation_output_key()` for transparent drivers.
* `"key_derivation_output_key"`: called by `psa_key_derivation_output_key()` for transparent drivers when deriving an asymmetric key pair, and also for opaque drivers.
* `"key_derivation_abort"`: called by all key derivation functions of the PSA Cryptography API.
* `"key_derivation_oneshot"`: called by `psa_key_derivation_output_bytes()` and `psa_key_derivation_output_key()` when the output is derived from an opaque secret. Note: HKDF is currently the only algorithm that is supported for opaque key derivation.

A `"key_derivation_oneshot"` entry point for a driver with the prefix `"acme_opaque"`must have the following signature (assuming the `"names"` property is not used):
```
psa_status_t acme_opaque_key_derivation_oneshot(psa_algorithm_t alg,
                                                const psa_key_attributes_t *secret_key_attributes,
                                                const uint8_t *secret_key_buffer,
                                                size_t secret_key_size,
                                                const psa_key_derivation_input_buffer_t *input_array,
                                                size_t input_count,
                                                const psa_key_attributes_t *output_key_attributes,
                                                uint8_t *output_key_buffer,
                                                size_t output_key_size,
                                                size_t *output_key_length);
```

TODO: key input and output for opaque drivers; deterministic key generation for transparent drivers

### Driver entry points for key management

The driver entry points for key management differs significantly between [transparent drivers](#key-management-with-transparent-drivers) and [opaque drivers](#key-management-with-transparent-drivers). Refer to the applicable section for each driver type.

### Miscellaneous driver entry points

#### Driver initialization

A driver may declare an `"init"` entry point in a capability with no algorithm, key type or key size. If so, the core calls this entry point once during the initialization of the PSA Cryptography subsystem. If the init entry point of any driver fails, the initialization of the PSA Cryptography subsystem fails.

When multiple drivers have an init entry point, the order in which they are called is unspecified. It is also unspecified whether other drivers' `"init"` entry points are called if one or more init entry point fails.

On platforms where the PSA Cryptography implementation is a subsystem of a single application, the initialization of the PSA Cryptography subsystem takes place during the call to `psa_crypto_init()`. On platforms where the PSA Cryptography implementation is separate from the application or applications, the initialization of the PSA Cryptography subsystem takes place before or during the first time an application calls `psa_crypto_init()`.

The init entry point does not take any parameter.

### Combining multiple drivers

To declare a cryptoprocessor can handle both cleartext and wrapped keys, you need to provide two driver descriptions, one for a transparent driver and one for an opaque driver. You can use the mapping in capabilities' `"names"` property to arrange for multiple driver entry points to map to the same C function.

## Transparent drivers

### Key format for transparent drivers

The format of a key for transparent drivers is the same as in applications. Refer to the documentation of [`psa_export_key()`](https://armmbed.github.io/mbed-crypto/html/api/keys/management.html#c.psa_export_key) and [`psa_export_public_key()`](https://armmbed.github.io/mbed-crypto/html/api/keys/management.html#c.psa_export_public_key) in the PSA Cryptography API specification. For custom key types defined by an implementation, refer to the documentation of that implementation.

### Key management with transparent drivers

Transparent drivers may provide the following key management entry points:

* `"generate_key"`: called by `psa_generate_key()`, only when generating a key pair (key such that `PSA_KEY_TYPE_IS_ASYMMETRIC` is true).
* `"key_derivation_output_key"`: called by `psa_key_derivation_output_key()`, only when deriving a key pair (key such that `PSA_KEY_TYPE_IS_ASYMMETRIC` is true).
* `"export_public_key"`: called by the core to obtain the public key of a key pair. The core may call this function at any time to obtain the public key, which can be for `psa_export_public_key()` but also at other times, including during a cryptographic operation that requires the public key such as a call to `psa_verify_message()` on a key pair object.

Transparent drivers are not involved when importing, exporting, copying or destroying keys, or when generating or deriving symmetric keys.

### Fallback

Sometimes cryptographic accelerators only support certain cryptographic mechanisms partially. The capability description language allows specifying some restrictions, including restrictions on key sizes, but it cannot cover all the possibilities that may arise in practice. Furthermore, it may be desirable to deploy the same binary image on different devices, only some of which have a cryptographic accelerators.
For these purposes, a transparent driver can declare that it only supports a [capability](#driver-description-capability) partially, by setting the capability's `"fallback"` property to true.

If a transparent driver entry point is part of a capability which has a true `"fallback"` property and returns `PSA_ERROR_NOT_SUPPORTED`, the core will call the next transparent driver that supports the mechanism, if there is one. The core considers drivers in the order given by the [driver description list](#driver-description-list).

If all the available drivers have fallback enabled and return `PSA_ERROR_NOT_SUPPORTED`, the core will perform the operation using built-in code.
As soon as a driver returns any value other than `PSA_ERROR_NOT_SUPPORTED` (`PSA_SUCCESS` or a different error code), this value is returned to the application, without attempting to call any other driver or built-in code.

If a transparent driver entry point is part of a capability where the `"fallback"` property is false or omitted, the core should not include any other code for this capability, whether built in or in another transparent driver.

## Opaque drivers

Opaque drivers allow a PSA Cryptography implementation to delegate cryptographic operations to a separate environment that might not allow exporting key material in cleartext. The opaque driver interface is designed so that the core never inspects the representation of a key. The opaque driver interface is designed to support two subtypes of cryptoprocessors:

* Some cryptoprocessors do not have persistent storage for individual keys. The representation of a key is the key material wrapped with a master key which is located in the cryptoprocessor and never exported from it. The core stores this wrapped key material on behalf of the cryptoprocessor.
* Some cryptoprocessors have persistent storage for individual keys. The representation of a key is an identifier such as label or slot number. The core stores this identifier.

### Key format for opaque drivers

The format of a key for opaque drivers is an opaque blob. The content of this blob is fully up to the driver. The core merely stores this blob.

Note that since the core stores the key context blob as it is in memory, it must only contain data that is meaningful after a reboot. In particular, it must not contain any pointers or transient handles.

The `"key_context"` property in the [driver description](#driver-description-top-level-element) specifies how to calculate the size of the key context as a function of the key type and size. This is an object with the following properties:

* `"base_size"` (integer or string, optional): this many bytes are included in every key context. If omitted, this value defaults to 0.
* `"key_pair_size"` (integer or string, optional): this many bytes are included in every key context for a key pair. If omitted, this value defaults to 0.
* `"public_key_size"` (integer or string, optional): this many bytes are included in every key context for a public key. If omitted, this value defaults to 0.
* `"symmetric_factor"` (integer or string, optional): every key context for a symmetric key includes this many times the key size. If omitted, this value defaults to 0.
* `"store_public_key"` (boolean, optional): If specified and true, for a key pair, the key context includes space for the public key. If omitted or false, no additional space is added for the public key.
* `"size_function"` (string, optional): the name of a function that returns the number of bytes that the driver needs in a key context for a key. This may be a pointer to function. This must be a C identifier; more complex expressions are not permitted. If the core uses this function, it supersedes all the other properties.

The integer properties must be C language constants. A typical value for `"base_size"` is `sizeof(acme_key_context_t)` where `acme_key_context_t` is a type defined in a driver header file.

#### Size of a dynamically allocated key context

If the core supports dynamic allocation for the key context and chooses to use it, and the driver specification includes the `"size_function"` property, the size of the key context is at least
```
size_function(key_type, key_bits)
```
where `size_function` is the function named in the `"size_function"` property, `key_type` is the key type and `key_bits` is the key size in bits. The prototype of the size function is
```
size_t size_function(psa_key_type_t key_type, size_t key_bits);
```

#### Size of a statically allocated key context

If the core does not support dynamic allocation for the key context or chooses not to use it, or if the driver specification does not include the `"size_function"` property, the size of the key context for a key of type `key_type` and of size `key_bits` bits is:

* For a key pair (`PSA_KEY_TYPE_IS_KEY_PAIR(key_type)` is true):
    ```
    base_size + key_pair_size + public_key_overhead
    ```
    where `public_key_overhead = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE(key_type, key_bits)` if the `"store_public_key"` property is true and `public_key_overhead = 0` otherwise.

* For a public key (`PSA_KEY_TYPE_IS_PUBLIC_KEY(key_type)` is true):
    ```
    base_size + public_key_size
    ```

* For a symmetric key (not a key pair or public key):
    ```
    base_size + symmetric_factor * key_bytes
    ```
    where `key_bytes = ((key_bits + 7) / 8)` is the key size in bytes.

#### Key context size for a secure element with storage

If the key is stored in the secure element and the driver only needs to store a label for the key, use `"base_size"` as the size of the label plus any other metadata that the driver needs to store, and omit the other properties.

If the key is stored in the secure element, but the secure element does not store the public part of a key pair and cannot recompute it on demand, additionally use the `"store_public_key"` property with the value `true`. Note that this only influences the size of the key context: the driver code must copy the public key to the key context and retrieve it on demand in its `export_public_key` entry point.

#### Key context size for a secure element without storage

If the key is stored in wrapped form outside the secure element, and the wrapped form of the key plus any metadata has up to *N* bytes of overhead, use *N* as the value of the `"base_size"` property and set the `"symmetric_factor"` property to 1. Set the `"key_pair_size"` and `"public_key_size"` properties appropriately for the largest supported key pair and the largest supported public key respectively.

### Key management with opaque drivers

Opaque drivers may provide the following key management entry points:

* `"export_key"`: called by `psa_export_key()`, or by `psa_copy_key()` when copying a key from or to a different [location](#lifetimes-and-locations).
* `"export_public_key"`: called by the core to obtain the public key of a key pair. The core may call this entry point at any time to obtain the public key, which can be for `psa_export_public_key()` but also at other times, including during a cryptographic operation that requires the public key such as a call to `psa_verify_message()` on a key pair object.
* `"import_key"`: called by `psa_import_key()`, or by `psa_copy_key()` when copying a key from another location.
* `"generate_key"`: called by `psa_generate_key()`.
* `"key_derivation_output_key"`: called by `psa_key_derivation_output_key()`.
* `"copy_key"`: called by `psa_copy_key()` when copying a key within the same [location](#lifetimes-and-locations).

In addition, secure elements that store the key material internally must provide the following two entry points:

* `"allocate_key"`: called by `psa_import_key()`, `psa_generate_key()`, `psa_key_derivation_output_key()` or `psa_copy_key()` before creating a key in the location of this driver.
* `"destroy_key"`: called by `psa_destroy_key()`.

#### Key creation in a secure element without storage

This section describes the key creation process for secure elements that do not store the key material. The driver must obtain a wrapped form of the key material which the core will store. A driver for such a secure element has no `"allocate_key"` or `"destroy_key"` entry point.

When creating a key with an opaque driver which does not have an `"allocate_key"` or `"destroy_key"` entry point:

1. The core allocates memory for the key context.
2. The core calls the driver's import, generate, derive or copy entry point.
3. The core saves the resulting wrapped key material and any other data that the key context may contain.

To destroy a key, the core simply destroys the wrapped key material, without invoking driver code.

#### Key management in a secure element with storage

This section describes the key creation and key destruction processes for secure elements that have persistent storage for the key material. A driver for such a secure element has two mandatory entry points:

* `"allocate_key"`: this function obtains an internal identifier for the key. This may be, for example, a unique label or a slot number.
* `"destroy_key"`: this function invalidates the internal identifier and destroys the associated key material.

These functions have the following prototypes for a driver with the prefix `"acme"`:
```
psa_status_t acme_allocate_key(const psa_key_attributes_t *attributes,
                               uint8_t *key_buffer,
                               size_t key_buffer_size);
psa_status_t acme_destroy_key(const psa_key_attributes_t *attributes,
                              const uint8_t *key_buffer,
                              size_t key_buffer_size);
```

When creating a persistent key with an opaque driver which has an `"allocate_key"` entry point:

1. The core calls the driver's `"allocate_key"` entry point. This function typically allocates an internal identifier for the key without modifying the state of the secure element and stores the identifier in the key context. This function should not modify the state of the secure element. It may modify the copy of the persistent state of the driver in memory.

1. The core saves the key context to persistent storage.

1. The core calls the driver's key creation entry point.

1. The core saves the updated key context to persistent storage.

If a failure occurs after the `"allocate_key"` step but before the call to the second driver entry point, the core will do one of the following:

* Fail the creation of the key without indicating this to the driver. This can happen, in particular, if the device loses power immediately after the key allocation entry point returns.
* Call the driver's `"destroy_key"` entry point.

To destroy a key, the core calls the driver's `"destroy_key"` entry point.

Note that the key allocation and destruction entry points must not rely solely on the key identifier in the key attributes to identify a key. Some implementations of the PSA Cryptography API store keys on behalf of multiple clients, and different clients may use the same key identifier to designate different keys. The manner in which the core distinguishes keys that have the same identifier but are part of the key namespace for different clients is implementation-dependent and is not accessible to drivers. Some typical strategies to allocate an internal key identifier are:

* Maintain a set of free slot numbers which is stored either in the secure element or in the driver's persistent storage. To allocate a key slot, find a free slot number, mark it as occupied and store the number in the key context. When the key is destroyed, mark the slot number as free.
* Maintain a monotonic counter with a practically unbounded range in the secure element or in the driver's persistent storage. To allocate a key slot, increment the counter and store the current value in the key context. Destroying a key does not change the counter.

TODO: explain constraints on how the driver updates its persistent state for resilience

TODO: some of the above doesn't apply to volatile keys

#### Key creation entry points in opaque drivers

The key creation entry points have the following prototypes for a driver with the prefix `"acme"`:

```
psa_status_t acme_import_key(const psa_key_attributes_t *attributes,
                             const uint8_t *data,
                             size_t data_length,
                             uint8_t *key_buffer,
                             size_t key_buffer_size);
psa_status_t acme_generate_key(const psa_key_attributes_t *attributes,
                               uint8_t *key_buffer,
                               size_t key_buffer_size);
```

If the driver has an [`"allocate_key"` entry point](#key-management-in-a-secure-element-with-storage), the core calls the `"allocate_key"` entry point with the same attributes on the same key buffer before calling the key creation entry point.

TODO: derivation, copy

#### Key export entry points in opaque drivers

The key export entry points have the following prototypes for a driver with the prefix `"acme"`:

```
psa_status_t acme_export_key(const psa_key_attributes_t *attributes,
                             const uint8_t *key_buffer,
                             size_t key_buffer_size);
                             uint8_t *data,
                             size_t data_size,
                             size_t *data_length);
psa_status_t acme_export_public_key(const psa_key_attributes_t *attributes,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size);
                                    uint8_t *data,
                                    size_t data_size,
                                    size_t *data_length);
```

The core will only call `acme_export_public_key` on a private key. Drivers implementers may choose to store the public key in the key context buffer or to recalculate it on demand. If the key context includes the public key, it needs to have an adequate size; see [“Key format for opaque drivers”](#key-format-for-opaque-drivers).

The core guarantees that the size of the output buffer (`data_size`) is sufficient to export any key with the given attributes. The driver must set `*data_length` to the exact size of the exported key.

### Opaque driver persistent state

The core maintains persistent state on behalf of an opaque driver. This persistent state consists of a single byte array whose size is given by the `"persistent_state_size"` property in the [driver description](#driver-description-top-level-element).

The core loads the persistent state in memory before it calls the driver's [init entry point](#driver-initialization). It is adjusted to match the size declared by the driver, in case a driver upgrade changes the size:

* The first time the driver is loaded on a system, the persistent state is all-bits-zero.
* If the stored persistent state is smaller than the declared size, the core pads the persistent state with all-bits-zero at the end.
* If the stored persistent state is larger than the declared size, the core truncates the persistent state to the declared size.

The core provides the following callback functions, which an opaque driver may call while it is processing a call from the driver:
```
psa_status_t psa_crypto_driver_get_persistent_state(uint_8_t **persistent_state_ptr);
psa_status_t psa_crypto_driver_commit_persistent_state(size_t from, size_t length);
```

`psa_crypto_driver_get_persistent_state` sets `*persistent_state_ptr` to a pointer to the first byte of the persistent state. This pointer remains valid during a call to a driver entry point. Once the entry point returns, the pointer is no longer valid. The core guarantees that calls to `psa_crypto_driver_get_persistent_state` within the same entry point return the same address for the persistent state, but this address may change between calls to an entry point.

`psa_crypto_driver_commit_persistent_state` updates the persistent state in persistent storage. Only the portion at byte offsets `from` inclusive to `from + length` exclusive is guaranteed to be updated; it is unspecified whether changes made to other parts of the state are taken into account. The driver must call this function after updating the persistent state in memory and before returning from the entry point, otherwise it is unspecified whether the persistent state is updated.

The core will not update the persistent state in storage while an entry point is running except when the entry point calls `psa_crypto_driver_commit_persistent_state`. It may update the persistent state in storage after an entry point returns.

In a multithreaded environment, the driver may only call these two functions from the thread that is executing the entry point.

## How to use drivers from an application

### Using transparent drivers

Transparent drivers linked into the library are automatically used for the mechanisms that they implement.

### Using opaque drivers

Each opaque driver is assigned a [location](#lifetimes-and-locations). The driver is invoked for all actions that use a key in that location. A key's location is indicated by its lifetime. The application chooses the key's lifetime when it creates the key.

For example, the following snippet creates an AES-GCM key which is only accessible inside the secure element designated by the location `PSA_KEY_LOCATION_acme`.
```
psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_acme));
psa_set_key_identifer(&attributes, 42);
psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
psa_set_key_size(&attributes, 128);
psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
psa_key_handle_t handle = 0;
psa_generate_key(&attributes, &handle);
```

## Using opaque drivers from an application

### Lifetimes and locations

The PSA Cryptography API, version 1.0.0, defines [lifetimes](https://armmbed.github.io/mbed-crypto/html/api/keys/attributes.html?highlight=psa_key_lifetime_t#c.psa_key_lifetime_t) as an attribute of a key that indicates where the key is stored and which application and system actions will create and destroy it. The lifetime is expressed as a 32-bit value (`typedef uint32_t psa_key_lifetime_t`). An upcoming version of the PSA Cryptography API defines more structure for lifetime values to separate these two aspects of the lifetime:

* Bits 0–7 are a _persistence level_. This value indicates what device management actions can cause it to be destroyed. In particular, it indicates whether the key is volatile or persistent.
* Bits 8–31 are a _location indicator_. This value indicates where the key material is stored and where operations on the key are performed. Location values can be stored in a variable of type `psa_key_location_t`.

An opaque driver is attached to a specific location. Keys in the default location (`PSA_KEY_LOCATION_LOCAL_STORAGE = 0`) are transparent: the core has direct access to the key material. For keys in a location that is managed by an opaque driver, only the secure element has access to the key material and can perform operations on the key, while the core only manipulates a wrapped form of the key or an identifier of the key.

### Creating a key in a secure element

The core defines a compile-time constant for each opaque driver indicating its location called `PSA_KEY_LOCATION_`*prefix* where *prefix* is the value of the `"prefix"` property in the driver description. For convenience, Mbed TLS also declares a compile-time constant for the corresponding lifetime with the default persistence called `PSA_KEY_LIFETIME_`*prefix*. Therefore, to declare an opaque key in the location with the prefix `foo` with the default persistence, call `psa_set_key_lifetime` during the key creation as follows:
```
psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_foo);
```

To declare a volatile key:
```
psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_LOCATION_foo,
        PSA_KEY_PERSISTENCE_VOLATILE));
```

Generally speaking, to declare a key with a specified persistence:
```
psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_LOCATION_foo,
        persistence));
```

## Open questions

### Driver declarations

#### Declaring driver entry points

The core may want to provide declarations for the driver entry points so that it can compile code using them. At the time of writing this paragraph, the driver headers must define types but there is no obligation for them to declare functions. The core knows what the function names and argument types are, so it can generate prototypes.

It should be ok for driver functions to be function-like macros or function pointers.

#### Driver location values

How does a driver author decide which location values to use? It should be possible to combine drivers from different sources. Use the same vendor assignment as for PSA services?

Can the driver assembly process generate distinct location values as needed? This can be convenient, but it's also risky: if you upgrade a device, you need the location values to be the same between builds.

The current plan is for Arm to maintain a registry of vendors and assign a location namespace to each vendor. Parts of the namespace would be reserved for implementations and integrators.

#### Multiple transparent drivers

When multiple transparent drivers implement the same mechanism, which one is called? The first one? The last one? Unspecified? Or is this an error (excluding capabilities with fallback enabled)?

The current choice is that the first one is used, which allows having a preference order on drivers, but may mask integration errors.

### Driver function interfaces

#### Driver function parameter conventions

Should 0-size buffers be guaranteed to have a non-null pointers?

Should drivers really have to cope with overlap?

Should the core guarantee that the output buffer size has the size indicated by the applicable buffer size macro (which may be an overestimation)?

### Partial computations in drivers

#### Substitution points

Earlier drafts of the driver interface had a concept of _substitution points_: places in the calculation where a driver may be called. Some hardware doesn't do the whole calculation, but only the “main” part. This goes both for transparent and opaque drivers. Some common examples:

* A processor that performs the RSA exponentiation, but not the padding. The driver should be able to leverage the padding code in the core.
* A processor that performs a block cipher operation only for a single block, or only in ECB mode, or only in CTR mode. The core would perform the block mode (CBC, CTR, CCM, ...).

This concept, or some other way to reuse portable code such as specifying inner functions like `psa_rsa_pad` in the core, should be added to the specification.

### Key management

#### Mixing drivers in key derivation

How does `psa_key_derivation_output_key` work when the extraction part and the expansion part use different drivers?

#### Public key calculation

ECC key pairs are represented as the private key value only. The public key needs to be calculated from that. Both transparent drivers and opaque drivers provide a function to calculate the public key (`"export_public_key"`).

The specification doesn't mention when the public key might be calculated. The core may calculate it on creation, on demand, or anything in between. Opaque drivers have a choice of storing the public key in the key context or calculating it on demand and can convey whether the core should store the public key with the `"store_public_key"` property. Is this good enough or should the specification include non-functional requirements?

### Opaque drivers

#### Opaque driver persistent state

The driver is allowed to update the state at any time. Is this ok?

An example use case for updating the persistent state at arbitrary times is to renew a key that is used to encrypt communications between the application processor and the secure element.

`psa_crypto_driver_get_persistent_state` does not identify the calling driver, so the driver needs to remember which driver it's calling. This may require a thread-local variable in a multithreaded core. Is this ok?

<!--
Local Variables:
time-stamp-line-limit: 40
time-stamp-start: "Time-stamp: *\""
time-stamp-end: "\""
time-stamp-format: "%04Y/%02m/%02d %02H:%02M:%02S %Z"
time-stamp-time-zone: "GMT"
End:
-->
