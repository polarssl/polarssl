#!/usr/bin/env python3
"""
This file is part of Mbed TLS (https://tls.mbed.org)

Copyright (c) 2018, Arm Limited, All Rights Reserved

Purpose

This script confirms that the naming of all symbols and identifiers in mbed
TLS are consistent with the house style and are also self-consistent.
"""
import os
import sys
import traceback
import re
import shutil
import subprocess
import logging


class NameCheck(object):
    def __init__(self):
        self.log = None
        self.setup_logger()
        self.check_repo_path()
        self.return_code = 0
        self.excluded_files = ["compat-1.3.h"]
        self.header_files = self.get_files(os.path.join("include", "mbedtls"))
        self.library_files = self.get_files("library")
        self.macros = []
        self.MBED_names = []
        self.enum_consts = []
        self.identifiers = []
        self.actual_macros = []
        self.symbols = []
        self.macro_pattern = r"#define (?P<macro>\w+)"
        self.MBED_pattern = r"\bMBED.+?_[A-Z0-9_]*"
        self.symbol_pattern = r"^\S+( [0-9A-Fa-f]+)* . _*(?P<symbol>\w+)"
        self.identifier_check_pattern = r"^mbedtls_[0-9a-z_]*[0-9a-z]$"
        self.decls_pattern = (
            r"^(extern \"C\"|(typedef )?(struct|enum)( {)?$|};?$|$)"
        )
        self.macro_const_check_pattern = (
            r"^MBEDTLS_[0-9A-Z_]*[0-9A-Z]$|^YOTTA_[0-9A-Z_]*[0-9A-Z]$"
        )
        self.typo_check_pattern = r"XXX|__|_$|^MBEDTLS_.*CONFIG_FILE$"
        self.non_macros = (
            "asm", "inline", "EMIT", "_CRT_SECURE_NO_DEPRECATE", "MULADDC_"
        )

    def set_return_code(self, return_code):
        if return_code > self.return_code:
            self.return_code = return_code

    def setup_logger(self):
        self.log = logging.getLogger()
        self.log.setLevel(logging.INFO)
        self.log.addHandler(logging.StreamHandler())

    def check_repo_path(self):
        current_dir = os.path.realpath('.')
        root_dir = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.realpath(__file__))))
        if current_dir != root_dir:
            raise Exception("Must be run from Mbed TLS root")

    def get_files(self, directory):
        filenames = []
        for root, dirs, files in sorted(os.walk(directory)):
            for filename in sorted(files):
                if (filename not in self.excluded_files and
                        filename.endswith((".c", ".h"))):
                    filenames.append(os.path.join(root, filename))
        return filenames

    def get_macros(self):
        for header_file in self.header_files:
            with open(header_file, "r") as header:
                for line in iter(header.readline, ""):
                    macro = re.search(self.macro_pattern, line)
                    if (macro and not
                            macro.group("macro").startswith(self.non_macros)):
                        self.macros.append((macro.group("macro"), header_file))
        self.macros = list(set(self.macros))

    def get_MBED_names(self):
        for file_group in [self.header_files, self.library_files]:
            for filename in file_group:
                with open(filename, "r") as f:
                    for line in iter(f.readline, ""):
                        mbed_names = re.findall(self.MBED_pattern, line)
                        if mbed_names:
                            for name in mbed_names:
                                self.MBED_names.append((name, filename))
        self.MBED_names = list(set(self.MBED_names))

    def get_enum_consts(self):
        for header_file in self.header_files:
            state = 0
            with open(header_file, "r") as header:
                for line in iter(header.readline, ""):
                    if state is 0 and re.match(r"^(typedef )?enum {", line):
                        state = 1
                    elif state is 0 and re.match(r"^(typedef )?enum", line):
                        state = 2
                    elif state is 2 and re.match(r"^{", line):
                        state = 1
                    elif state is 1 and re.match(r"^}", line):
                        state = 0
                    elif state is 1:
                        enum_const = re.match(r"^\s*(?P<enum_const>\w+)", line)
                        if enum_const:
                            self.enum_consts.append(
                                (enum_const.group("enum_const"), header_file)
                            )

    def line_contains_declaration(self, line):
        return (re.match(r"^[^ /#{]", line)
                and not re.match(self.decls_pattern, line))

    def get_identifier_from_declaration(self, declaration):
        identifier = re.search(
            r"([a-zA-Z_][a-zA-Z0-9_]*)\(|"
            r"\(\*(.+)\)\(|"
            r"(\w+)\W*$",
            declaration
        )
        if identifier:
            for group in identifier.groups():
                if group:
                    return group
        self.log.error(declaration)
        raise Exception("No identifier found")

    def get_identifiers(self):
        for header_file in self.header_files:
            with open(header_file, "r") as header:
                for line in iter(header.readline, ""):
                    if self.line_contains_declaration(line):
                        self.identifiers.append(
                            (self.get_identifier_from_declaration(line),
                             header_file)
                        )

    def get_symbols(self):
        try:
            shutil.copy("include/mbedtls/config.h",
                        "include/mbedtls/config.h.bak")
            subprocess.run(
                ["perl", "scripts/config.pl", "full"],
                encoding=sys.stdout.encoding,
                check=True
            )
            my_environment = os.environ.copy()
            my_environment["CFLAGS"] = "-fno-asynchronous-unwind-tables"
            subprocess.run(
                ["make", "clean", "lib"],
                env=my_environment,
                encoding=sys.stdout.encoding,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True
            )
            shutil.move("include/mbedtls/config.h.bak",
                        "include/mbedtls/config.h")
            nm_output = ""
            for lib in ["library/libmbedcrypto.a",
                        "library/libmbedtls.a",
                        "library/libmbedx509.a"]:
                nm_output += subprocess.run(
                    ["nm", "-og", lib],
                    encoding=sys.stdout.encoding,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=True
                ).stdout
            for line in nm_output.splitlines():
                if not re.match(r"^\S+: +U |^$|^\S+:$", line):
                    symbol = re.match(self.symbol_pattern, line)
                    if symbol:
                        self.symbols.append(symbol.group('symbol'))
                    else:
                        self.log.error(line)
            self.symbols.sort()
            subprocess.run(
                ["make", "clean"],
                encoding=sys.stdout.encoding,
                check=True
            )
        except subprocess.CalledProcessError as error:
            self.log.error(error)
            self.set_return_code(2)

    def check_symbols_declared_in_header(self):
        identifiers = [x[0] for x in self.identifiers]
        bad_names = []
        for symbol in self.symbols:
            if symbol not in identifiers:
                bad_names.append(symbol)
        if bad_names:
            self.set_return_code(1)
            self.log.info("Names of identifiers: FAIL")
            for name in bad_names:
                self.log.info(name)
        else:
            self.log.info("Names of identifiers: PASS")

    def check_group(self, group_to_check, check_pattern, name):
        bad_names = []
        for item in group_to_check:
            if not re.match(check_pattern, item[0]):
                bad_names.append("{} - {}".format(item[0], item[1]))
        if bad_names:
            self.set_return_code(1)
            self.log.info("Names of {}: FAIL".format(name))
            for name in bad_names:
                self.log.info(name)
        else:
            self.log.info("Names of {}: PASS".format(name))

    def check_for_typos(self):
        bad_names = []
        all_caps_names = list(set(
            [x[0] for x in self.actual_macros + self.enum_consts]
        ))
        for name in self.MBED_names:
            if name[0] not in all_caps_names:
                if not re.search(self.typo_check_pattern, name[0]):
                    bad_names.append("{} - {}".format(name[0], name[1]))
        if bad_names:
            self.set_return_code(1)
            self.log.info("Likely typos: FAIL")
            for name in bad_names:
                self.log.info(name)
        else:
            self.log.info("Likely typos: PASS")

    def get_names_from_source_code(self):
        self.log.info("Analysing source code...")
        self.get_macros()
        self.get_enum_consts()
        self.get_identifiers()
        self.get_symbols()
        self.get_MBED_names()
        self.actual_macros = list(set(self.macros) - set(self.identifiers))
        self.log.info("{} macros".format(len(self.macros)))
        self.log.info("{} enum-consts".format(len(self.enum_consts)))
        self.log.info("{} identifiers".format(len(self.identifiers)))
        self.log.info("{} exported-symbols".format(len(self.symbols)))

    def check_names(self):
        self.check_symbols_declared_in_header()
        for group, check_pattern, name in [
                (self.actual_macros, self.macro_const_check_pattern,
                 "actual-macros"),
                (self.enum_consts, self.macro_const_check_pattern,
                 "enum-consts"),
                (self.identifiers, self.identifier_check_pattern,
                 "identifiers")]:
            self.check_group(group, check_pattern, name)
        self.check_for_typos()


def run_main():
    try:
        name_check = NameCheck()
        name_check.get_names_from_source_code()
        name_check.check_names()
        sys.exit(name_check.return_code)
    except Exception:
        traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    run_main()
