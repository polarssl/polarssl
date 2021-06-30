#!/usr/bin/env python3
"""
Upgrade the Mbed TLS configuration file to the current version of Mbed TLS.

Please note that this script makes a best effort to achieve a correct
conversion, but it cannot handle all cases. Review the output manually.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import functools
import os
import re
import sys
from typing import Callable, List, Optional, Tuple

from mbedtls_dev import typing_util


V2_CONFIG = 'include/mbedtls/config.h'
"""Default configuration file name in Mbed TLS 2.x."""
DEFAULT_CONFIG = 'include/mbedtls/mbedtls_config.h'
"""Default configuration file name in Mbed TLS 3.x."""

C_COMMENT_RE = re.compile(r'/\*.*?\*/|//[^\n]*\n?', re.S)
"""Regex matching a comment in the C language."""


@functools.total_ordering
class VersionNumber:
    """An Mbed TLS version number."""

    VERSION_RE = re.compile(r'\A[0-9]+(?:\.[0-9]+)*\Z')

    def __init__(self, version: str) -> None:
        m = self.VERSION_RE.match(version)
        if not m:
            raise ValueError('Invalid version number: ' + version)
        self.parts = tuple(int(s) for s in version.split('.'))

    @staticmethod
    def _extend(parts1: Tuple[int, ...], parts2: Tuple[int, ...]) \
            -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
        if len(parts1) < len(parts2):
            return parts1 + (0,) * (len(parts2) - len(parts1)), parts2
        else:
            return parts1, parts2 + (0,) * (len(parts1) - len(parts2))

    def __lt__(self, other: 'VersionNumber') -> bool:
        me, them = self._extend(self.parts, other.parts)
        return me < them

    def __eq__(self, other) -> bool:
        if isinstance(other, VersionNumber):
            other_parts = other.parts
        else:
            other_parts = tuple(x for x in other)
            if not all(isinstance(x, int) for x in other_parts):
                return NotImplemented
        me, them = self._extend(self.parts, other_parts)
        return me == them

    def __str__(self) -> str:
        return '.'.join(str(n) for n in self.parts)

    def at_least(self, *parts: int) -> bool:
        """Whether this version is at least the specified vintage.

        For example: ``version.at_least(3, 0)`` is true if this object represents
        3, 3.x, 4.x, etc., but not 2.x.
        """
        me, them = self._extend(self.parts, parts)
        return me >= them

def version_number_from_c(code: str) -> VersionNumber:
    """Parse a C numeric version number such as MBEDTLS_VERSION_NUMBER.

    Only hexadecimal integer literals are currently supported.
    """
    code = re.sub(C_COMMENT_RE, r' ', code).strip()
    m = re.match(r'(0x[0-9a-f]+)[lu]*\Z', code, re.I)
    if not m:
        raise Exception('Unable to parse library version number in C: ' + code)
    number = int(code, 0)
    return VersionNumber('.'.join([str((number >> (8 * k)) & 0xff)
                                   for k in reversed(range(4))]))


def detect_input_file(options) -> Tuple[str, VersionNumber]:
    """Determine the input config file and its apparent version.

    This function only looks at the command line and the file name to
    guess the version. The content of the file may have additional information
    that allows a more precise determination of the input version.
    """
    if options.input:
        from_version = VersionNumber(options.from_version or '2')
        return options.input, from_version
    if options.from_version:
        from_version = VersionNumber(options.from_version)
        if from_version.at_least(3):
            return DEFAULT_CONFIG, from_version
        else:
            return V2_CONFIG, from_version
    if os.path.exists(DEFAULT_CONFIG):
        return DEFAULT_CONFIG, VersionNumber('3')
    elif os.path.exists(V2_CONFIG):
        return V2_CONFIG, VersionNumber('2')
    else:
        raise Exception('No Mbed TLS configuration file found.')


class Directive:
    """Information about a C preprocessor directive."""
    #pylint: disable=too-few-public-methods

    START_RE = re.compile(r'\s*#\s*(\w+)(?:\s+(\w+))?')

    def __init__(self, text: str) -> None:
        m = self.START_RE.match(text)
        if not m:
            raise ValueError('Unable to parse preprocessor directive: ' + text)
        self.name = m.group(1) #type: str
        self.word = m.group(2) #type: Optional[str]
        self.trail = text[m.end():] #type: str


def upgrader(before_string: str) -> Callable[['Upgrader'], 'Upgrader']:
    """Decorator for configuration upgrader methods.

    To declare a method of the `Configuration` class as an upgrader,
    decorate it with ``@upgrader(VERSION)`` (e.g. ``@upgrader('3.0')``).
    The upgrader will be applied if the old configuration version is less
    than VERSION. In other words, it will be called when upgrading to or
    past VERSION, but not when upgrading from VERSION or newer.

    An upgrader method must take no arguments other than self and return
    nothing.
    """
    before_version = VersionNumber(before_string)
    def register(func: 'Upgrader') -> 'Upgrader':
        setattr(func, 'before_version', before_version)
        return func
    return register

class Configuration():
    """A representation of an Mbed TLS configuration file."""

    def reset(self) -> None:
        self.content = [] #type: List[str]
        self.explicit_version = None #type: Optional[VersionNumber]
        self.content_version = self.presumed_version

    def __init__(self, input_version: VersionNumber) -> None:
        self.presumed_version = input_version #type: VersionNumber
        self.reset()

    CHUNK_RE = re.compile(r'|'.join([
        r'/\*.*?\*/|//[^\n]*\n?', # comment
        r'"(?:\\.|[^\\"])"', # string literal
        r'#.*?(?:\Z|[^\\\n]\n)', # preprocessor directive
        r'\n[\t ]*', # line break
        r'[^\n"#/]', # other
        '[\t ]*.']), re.S)

    def parse(self, text: str) -> None:
        """Load the configuration from a string."""
        self.reset()
        pos = 0
        while pos < len(text):
            m = self.CHUNK_RE.match(text, pos)
            assert m is not None
            self.content.append(m.group(0))
            pos = m.end()

    def load(self, filename: str) -> None:
        """Load the configuration from a file."""
        text = open(filename).read()
        self.parse(text)

    @staticmethod
    def parse_directive(chunk: str) -> Optional[Directive]:
        """Parse a C preprocessor directive line (beginning with '#')."""
        if chunk[0] == '#':
            return Directive(chunk)
        else:
            return None

    def analyze(self) -> None:
        """Analyze the loaded configuration.

        Call this method once after loading the configuration and before
        doing an upgrade.
        """
        # Some attributes set in this function are initialized in reset().
        # Mypy copes, but pylint is angry.
        #pylint: disable=attribute-defined-outside-init
        for chunk in self.content:
            d = self.parse_directive(chunk)
            if d and d.name == 'define' and d.word == 'MBEDTLS_CONFIG_VERSION':
                self.explicit_version = version_number_from_c(d.trail)
                self.content_version = self.explicit_version

    def upgrade(self) -> None:
        """Upgrade the configuration to the current version.

        You must load a configuration and call `analyze` first.
        """
        for method_name in dir(self):
            if method_name.startswith('_'):
                continue
            method = getattr(self, method_name)
            if not hasattr(method, '__call__'):
                continue
            if not hasattr(method, 'before_version'):
                continue
            before_version = getattr(method, 'before_version')
            assert isinstance(before_version, VersionNumber)
            if self.content_version < before_version:
                method()

    @staticmethod
    def maybe_backup(filename: str) -> None:
        """If the specified file exists, move it to a backup file."""
        if os.path.exists(filename):
            os.replace(filename, filename + '.bak')

    def write(self, out: typing_util.Writable) -> None:
        """Write the configuration to the specified output stream."""
        for chunk in self.content:
            out.write(chunk)

    def save(self, filename: str) -> None:
        """Save the configuration to the specified file.

        If the output file already exists, back it up first.
        """
        self.maybe_backup(filename)
        with open(filename, 'w') as out:
            self.write(out)

Upgrader = Callable[[Configuration], None]
"""The type of configuration upgrader methods."""



def convert_config(
        input_version: VersionNumber,
        input_file: str,
        output_file: str
) -> None:
    """Upgrade the configuration to the current Mbed TLS version.

    input_version is the presumed version of the old configuration. It may be
    overridden if the version can be inferred from the content.

    output_file can be '-' to read from standard input.
    output_file can be '-' to write to standard output.
    """
    configuration = Configuration(input_version)
    if input_file == '-':
        configuration.parse(sys.stdin.read())
    else:
        configuration.load(input_file)
    configuration.analyze()
    configuration.upgrade()
    if output_file == '-':
        configuration.write(sys.stdout)
    else:
        configuration.save(output_file)

def main(*args) -> None:
    """Process the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--from-version', metavar='VERSION',
                        help=('Assume input is for this version '
                              '(default: autodetected; '
                              'overridden by an explicit declaration in the file)'))
    parser.add_argument('--output', '-o', metavar='OUTPUT_FILE',
                        default=DEFAULT_CONFIG,
                        help='Output file (default: {})'.format(DEFAULT_CONFIG))
    parser.add_argument('input', metavar='INPUT_FILE', nargs='?',
                        help=('Current configuration file (default: {} or {})'
                              .format(V2_CONFIG, DEFAULT_CONFIG)))
    options = parser.parse_args(args)
    input_file, input_version = detect_input_file(options)
    convert_config(input_version, input_file, options.output)

if __name__ == '__main__':
    main(*sys.argv[1:])
