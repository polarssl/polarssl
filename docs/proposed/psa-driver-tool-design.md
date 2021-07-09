Requirements for PSA driver wrapper code generation
===================================================

This document contains design requirements for the tooling in Mbed TLS to generate wrapper code for PSA drivers.

## Role of the driver wrapper code

The driver interface specification describes the deliverables of a driver as consisting of C source and header files and a JSON driver description. In order to build Mbed TLS, drivers must be fully specified by C code. The goal of this document is to describe how Mbed TLS **combines JSON files from multiple drivers into driver wrapper code written in C**.

The job of the driver wrapper code is to dispatch requests to use a cryptographic mechanism to the appropriate implementation of this mechanism, either built-in code (code that ships with Mbed TLS) or code from a third-party driver.

## Applicable specifications

* [Driver interface](psa-driver-interface.html): for driver writers (and PSA crypto core implementers). specification of the C interfaces of drivers and of JSON driver descriptions. Mostly complete.
* [Driver developer's guide](psa-driver-developer-guide.html): for driver writers. Concrete steps to write a driver and provide the necessary files to use it in Mbed TLS. Work in progress.
* [Driver integration guide](psa-driver-integration-guide.html): for platform integrators, i.e. people who build Mbed TLS with a specific set of drivers. Concrete steps to select and configure drivers. Work in progress.
* [Conditional inclusion of cryptographic mechanisms](psa-conditional-inclusion-c.html): for application writers. explains how to build Mbed TLS with a subset of the available cryptographic mechanisms.

## User stories

[US.maintenance]
As an Mbed TLS maintainer,
I want the driver wrapper tooling to be well-documented and well-tested
so that I can add features and fix bug easily.

[US.portability]
As an Mbed TLS maintainer, platform integrator or application writer,
I want the driver wrapper tooling to use a minimal set of third-party tools
so that I can use it easily on a variety of systems.

[US.driver-basics]
As a hardware vendor,
I want to be able to write PSA crypto drivers that can be integrated into Mbed TLS
so that application writers can use my hardware easily.

[US.driver-binary]
As a hardware vendor,
I want to be able to ship my driver in binary form
because it is signed, or because it contains proprietary code.

[US.multiple-drivers]
As a platform integrator,
I want to combine drivers from multiple sources
so that I can use PSA crypto on a device with multiple cryptoprocessors.

[US.hardware-agnostic]
As a platform integrator,
I want to generate driver wrapper code
so that application writers only need to select which cryptographic mechanisms to include and don't need to care whether these mechanisms are implemented in software or in a cryptoprocessor.

[US.portable-bsp]
As a platform integrator,
I want to generate driver wrapper code into ready-to-compile C code
so that application writers can build their application on the platform of their choice with no extra tooling requirement.

[US.configurable-bsp]
As a platform integrator,
I want to generate driver wrapper code that can be adjusted for the mechanisms that the application uses
so that application writers can build an application without wasting code memory on features that they won't use.

[US.application-integration]
As an application writer,
I want to receive drivers in a form that I can use easily
so that I can focus on writing my application.

[US.application-size]
As an application writer,
I want to include only the driver features that I use
so that I don't waste the limited space for code on my device on features that I don't use.

[US.application-debugging]
As an application writer,
I want the driver wrapper code to be easy to debug
so that I can debug my application even when it calls a driver.

## Requirements

### Software dependencies

#### [Req.Tooling]

The generation of C wrapper code from JSON descriptions must be automated.

Rationale: [US.driver-basics]

#### [Req.Python]

The tooling for generating C wrapper code will be written in Python 3 (compatible with Python 3.6+).

Rationale: [US.maintenance], [US.portability]
Python 3 is the preferred scripting language for new work in Mbed TLS, especially for scripts that are meant to be used by users of the library.
Python 3.6 is the minimum required version in Mbed TLS 3.0.

#### [Req.Python-only]

The tooling for generating C wrapper code should work with just the Python standard library for basic operation. Optional advanced features may require third-party libraries.

Rationale: [US.maintenance], [US.portability], [US.portable-bsp]
While Python makes it easy to install third-party libraries, this can introduce version conflicts, opens the way to supply chain attacks, and doesn't work well in non-networked environments.

### Tool construction

#### [Req.modularity]

The tooling needs to be modular enough that it can be maintained and can evolve easily. Each module should have appropriate testing (unit tests, integration tests).

Rationale: [US.maintenance]

### Generated code quality

#### [Req.readability]

The generated C code must be reasonably easy to review and debug.

Rationale: [US.maintenance], [US.application-debugging]

The generated code does not need to conform to the Mbed TLS coding style.

Some examples of concrete things that make code easier to debug:

* Avoid overly complex preprocessor use.
* Don't put multiple statements on the same line.
* Use meaningful names for autogenerated local variables.
* Avoid extremely long lines.

### Generated code structure

#### [Req.conditional-mechanisms]

It must be possible to generate code where support for each mechanism is gated by the corresponding `PSA_WANT_xxx` option.

Rationale: [US.portable-bsp], [US.configurable-bsp], [US.application-size]

## Proposed design

### C generator core

Considered alternatives:

* Home-grown C generator: work in progress in https://github.com/gilles-peskine-arm/mbedtls/tree/psa-driver-cgen (`scripts/c_generator.py` and tests in `tests/scripts/test_c_generator.py`)
* Ready-made C generator from [pycparser](https://github.com/eliben/pycparser). Downside: needs an external module which contradicts [Req.python-only]; primarily a parsing library and unclear if it meets our needs for code generation.

### JSON parser

Rely on Python's built-in `json` module.

Optionally validate the JSON input with [`jsonschema`](https://python-jsonschema.readthedocs.io/). Validation must remain optional per [Req.Python-only] since this is an extra dependency.

### Description of built-in capabilities

TBD. As a JSON file in the same format as driver descriptions?

### Driver wrapper generation

A Python script `scripts/generate_psa_dispatch.py` that reads JSON driver descriptions and generates the C files (`.c` and `.h`) necessary to build the library.

### Integration in build scripts

As documented in the driver integration guide.

### Testing

A run of `all.sh` must validate the driver wrapper generation in a variety of configurations, through a combination of dedicated test components and by running it in configurations that are already being tested.

## Prototypes

* Driver wrapper generator in https://github.com/ARMmbed/mbedtls/pull/3313 (https://github.com/gilles-peskine-arm/mbedtls/tree/psa-unified-driver-prototype). Includes JSON parsing in `scripts/psa_crypto_driver_description.py` (with `jsonschema` for validation), `psa_crypto_driver_wrappers.py` containing very ad hoc C generation that didn't scale, integration in the make build system.
* Home-grown C generator: work in progress in https://github.com/ARMmbed/mbedtls/pull/4662 (https://github.com/gilles-peskine-arm/mbedtls/tree/psa-driver-cgen). `scripts/c_generator.py` and tests in `tests/scripts/test_c_generator.py`.

