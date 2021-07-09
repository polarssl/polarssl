#!/usr/bin/env python3
"""Simple static analysis on the abstract syntax tree of Mbed TLS.

This script uses the clang python bindings (pip3 install --user clang).
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
import glob
import os
import re
import sys
import typing
from typing import Iterable, Optional

import clang.cindex
from clang.cindex import Cursor, CursorKind, TranslationUnit


def showattr(arg, attr):
    try:
        return (attr, getattr(arg, attr))
    except AssertionError:
        return (attr, '<missing>')


class Ast:
    """Abstract representation of the source code."""

    def __init__(self, options) -> None:
        if options.clang_library_file:
            clang.cindex.Config.set_library_file(options.clang_library_file)
        self.parse_options = []
        for d in options.include:
            self.parse_options.append('-I' + d)
        self.index = clang.cindex.Index.create()
        self.files = {}
        self.load(*options.files)
        self.errors = 0

    def warn(self, node: Cursor, message, *args, **kwargs) -> None:
        try:
            filename = node.location.file.name
        except AttributeError:
            filename = '(unknown)'
        line = node.location.line
        sys.stderr.write('{}:{}: '.format(filename, line) +
                         message.format(*args, **kwargs) +
                         '\n')

    def error(self, node: Cursor, message, *args, **kwargs) -> None:
        self.errors += 1
        self.warn(node, message, *args, **kwargs)

    def load(self, *filenames: str) -> None:
        for filename in filenames:
            self.files[filename] = self.index.parse(filename,
                                                    self.parse_options)

    def deparen(self, node: Cursor) -> Cursor:
        children = list(node.get_children())
        if len(children) != 1:
            return node
        child = children[0]
        if node.kind in {CursorKind.PAREN_EXPR, CursorKind.UNEXPOSED_EXPR}:
            return self.deparen(child)
        return node

    _printf_format_types = {
        'd': 'int',
        'ld': 'long',
        'lld': 'long long',
        'u': 'unsigned int',
        'lu': 'unsigned long',
        'llu': 'unsigned long long',
        's': 'char *',
        'zu': 'size_t',
    }
    @classmethod
    def get_printf_format_type(cls, spec: str) -> Optional[str]:
        # Remove leading %, flags, width, precision
        spec = re.sub(r'[ #*+\-.0-9]+', r'', spec[1:])
        # Canonicalize certain types
        if spec[-1] in 'oxX':
            spec = spec[:-1] + 'u'
        return cls._printf_format_types.get(spec)

    @staticmethod
    def dequalify_type(type: str) -> str:
        """Remove type qualifiers from type."""
        type = re.sub(r'\bconst *', r'', type)
        return type

    @staticmethod
    def promote_type(type: str, signed: bool) -> str:
        """Promote the given C type.

        Return the promoted type or an equivalent.

        If signed is true, return int instead of unsigned if it fits.
        """
        if type in {'signed char', 'short',
                    'int8_t', 'int16_t', 'int32_t'}:
            return 'int'
        if type in {'unsigned char', 'unsigned short',
                    'uint8_t', 'uint16_t'}:
            return 'int' if signed else 'unsigned int'
        if type == 'uint32_t':
            return 'unsigned int'
        return type

    def check_printf_argument(self, spec: str, expr: Cursor) -> None:
        expected_type = self.get_printf_format_type(spec)
        if expected_type is None:
            self.error(expr, 'Format not supported: {}', spec)
        actual_type = expr.type.spelling
        actual_type = self.dequalify_type(actual_type)
        expect_signed = re.match(r'(int|long|signed)\b', expected_type)
        actual_type = self.promote_type(actual_type, expect_signed)
        if expected_type != actual_type:
            self.error(expr, 'Invalid type for format {}: {}',
                       spec, actual_type)

    _printf_specifier_re = r'%[ #*+\-.0-9LZhjlqtz]*.' # approximate but good enough for our code
    def analyze_debug_print(self, node):
        all_arguments = tuple(map(self.deparen,
                                  tuple(node.get_children())[1:]))
        if node.spelling == 'mbedtls_debug_print_msg':
            format_string_expr = all_arguments[4]
            arguments = all_arguments[5:]
        else:
            raise Exception('printf-like function declared in analyze_file but not in analyze_debug_print')
        if format_string_expr.kind != CursorKind.STRING_LITERAL:
            self.warn(node, 'Format is not a string literal')
        format_string = format_string_expr.spelling
        specifiers = re.findall(self._printf_specifier_re, format_string)
        specifiers = [spec for spec in specifiers if spec != '%%']
        if len(arguments) < len(specifiers):
            self.error(node, 'Not enough arguments for format ({} < {})',
                       len(arguments), len(specifiers))
        elif len(arguments) > len(specifiers):
            self.error(node, 'Too many arguments for format ({} > {})',
                       len(arguments), len(specifiers))
        for spec, arg in zip(specifiers, arguments):
            self.check_printf_argument(spec, arg)


    def analyze_function_calls(self,
                               functions: Iterable[str],
                               analyzer,
                               filename: str, tu: TranslationUnit) -> None:
        for node in tu.cursor.walk_preorder():
            if node.kind == CursorKind.CALL_EXPR and \
               node.spelling in functions:
                analyzer(node)

    def analyze_zeroize_calls(self, filename: str, tu: TranslationUnit) -> None:
        for node in tu.cursor.walk_preorder():
            if node.kind == CursorKind.CALL_EXPR and \
               node.spelling == 'mbedtls_platform_zeroize':
                ptr, size = map(self.deparen, tuple(node.get_children())[1:])
                print(ptr.kind, ptr.spelling, [self.deparen(child).kind for child in ptr.get_children()])
                print(size.kind, size.spelling, [self.deparen(child).kind for child in size.get_children()])

    def analyze_file(self, options,
                     filename: str, tu: TranslationUnit) -> None:
        if options.analyze_printf:
            self.analyze_function_calls('mbedtls_debug_print_msg',
                                        self.analyze_debug_print,
                                        filename, tu)
        if options.analyze_zeroize:
            self.analyze_zeroize_calls(filename, tu)

    def analyze_all_files(self, options) -> None:
        for filename in sorted(self.files.keys()):
            self.analyze_file(options, filename, self.files[filename])


def analyze_files(options):
    ast = Ast(options)
    ast.analyze_all_files(options)
    return ast.errors

def argparse_add_negative_options(parser):
    """Add --no-foo option for each --option that sets a boolean to True."""
    # This functionality is available in Python >=3.9 with
    # BooleanOptionalAction, but not in earlier versions.
    for action in parser._actions:
        if isinstance(action, argparse._StoreTrueAction):
            negated_option_strings = ['--no-' + s[2:]
                                      for s in action.option_strings
                                      if s.startswith('--')]
            if negated_option_strings:
                parser.add_argument(*negated_option_strings,
                                    action='store_false',
                                    dest=action.dest,
                                    default=action.default,
                                    help='Turn off ' + action.option_strings[0],
                )

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--analyze-printf',
                        action='store_true',
                        default=True,
                        help='Analyze printf() calls')
    parser.add_argument('--analyze-zeroize',
                        action='store_true',
                        default=False, # work in progress
                        help='Analyze mbedtls_platform_zeroize() calls')
    parser.add_argument('--clang-library-file',
                        help="Alternative location of libclang.so")
    parser.add_argument('--include', '-I',
                        action='append',
                        default=[],
                        help="""Directory to add to the header include path""")
    parser.add_argument('files', metavar='FILE', nargs='+',
                        help="""Files to analyze""")
    argparse_add_negative_options(parser)
    options = parser.parse_args()
    errors = analyze_files(options)
    if errors:
        sys.exit(1)

if __name__ == '__main__':
    main()
