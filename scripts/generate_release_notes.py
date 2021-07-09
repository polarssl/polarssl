#!/usr/bin/env python3
"""This script generates the MbedTLS release notes in markdown format.

It does this by calling assemble_changelog.py to generate the bulk of
content, and also inserting other content such as a brief description,
hashes for the tar and zip files containing the release, etc.

Returns 0 on success, 1 on failure.

Note: must be run from Mbed TLS root."""

# Copyright (c) 2020, Arm Limited, All Rights Reserved
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
#
# This file is part of Mbed TLS (https://tls.mbed.org)

import re
import sys
import os.path
import hashlib
import argparse
import tempfile
import subprocess

TEMPLATE = """## Description

These are the release notes for MbedTLS version {version}.

{description}

{changelog}

## Who should update

{whoshouldupdate}

## Checksum

The SHA256 hashes for the archives are:

```
{tarhash}  mbedtls-{version}.tar.gz
{ziphash}  mbedtls-{version}.zip
```
"""

WHO_SHOULD_UPDATE_DEFAULT = 'We recommend all affected users should \
update to take advantage of the bug fixes contained in this release at \
an appropriate point in their development lifecycle.'


CHECKLIST = '''Please review the release notes to ensure that all of the \
following are documented (if needed):
- Missing functionality
- Changes in functionality
- Known issues
'''


CUSTOM_WORDS = 'Hellman API APIs gz lifecycle Bugfix CMake inlined Crypto endian SHA xxx'


def sha256_digest(filename):
    """Read given file and return a SHA256 digest"""
    h = hashlib.sha256()
    with open(filename, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()


def error(text):
    """Display error message and exit"""
    print(f'ERROR: {text}')
    sys.exit(1)


def warn(text):
    """Display warning message"""
    print(f'WARNING: {text}')


def generate_content(args):
    """Return template populated with given content"""
    for field in ('version', 'tarhash', 'ziphash', 'changelog',
                  'description', 'whoshouldupdate'):
        if not field in args:
            error(f'{field} not specified')
    return TEMPLATE.format(**args)


def run_cmd(cmd, capture=True):
    """Run given command in a shell and return the command output"""
    # Note: [:-1] strips the trailing newline introduced by the shell.
    if capture:
        return subprocess.check_output(cmd, shell=True, input=None,
                                   universal_newlines=True)[:-1]
    else:
        subprocess.call(cmd, shell=True)


def parse_args(args):
    """Parse command line arguments and return cleaned up args"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-o', '--output', default='ReleaseNotes.md',
                        help='Output file (defaults to ReleaseNotes.md)')
    parser.add_argument('-t', '--tar', action='store',
                        help='Optional tar containing release (to generate hash)')
    parser.add_argument('-z', '--zip', action='store',
                        help='Optional zip containing release (to generate hash)')
    parser.add_argument('-d', '--description', action='store', required=True,
                        help='Short description of release (or name of file containing this)')
    parser.add_argument('-w', '--who', action='store', default=WHO_SHOULD_UPDATE_DEFAULT,
                        help='Optional short description of who should \
                            update (or name of file containing this)')
    args = parser.parse_args(args)

    # If these exist as files, interpret as files containing
    # desired content rather than literal content.
    for field in ('description', 'who'):
        if os.path.exists(getattr(args, field)):
            with open(getattr(args, field), 'r') as f:
                setattr(args, field, f.read())

    return args


def spellcheck(text):
    with tempfile.NamedTemporaryFile() as temp_file:
        with open(temp_file.name, 'w') as f:
            f.write(text)
        result = run_cmd(f'ispell -d american -w _- -a < {temp_file.name}')
        input_lines = text.splitlines()
        ispell_re = re.compile(r'& (\S+) \d+ \d+:.*')
        bad_words = set()
        bad_lines = set()
        line_no = 1
        for l in result.splitlines():
            if l.strip() == '':
                line_no += 1
            elif l.startswith('&'):
                m = ispell_re.fullmatch(l)
                word = m.group(1)
                if word.isupper():
                    # ignore all-uppercase words
                    pass
                elif "_" in word:
                    # part of a non-English 'word' like PSA_CRYPTO_ECC
                    pass
                elif word.startswith('-'):
                    # ignore flags
                    pass
                elif word in CUSTOM_WORDS:
                    # accept known-good words
                    pass
                else:
                    bad_words.add(word)
                    bad_lines.add(line_no)
        if bad_words:
            bad_lines = '\n'.join('    ' + input_lines[n] for n in sorted(bad_lines))
            bad_words = ', '.join(bad_words)
            warn('Release notes contain the following mis-spelled ' \
                        f'words: {bad_words}:\n{bad_lines}\n')


def gen_rel_notes(args):
    """Return release note content from given command line args"""
    # Get version by parsing version.h. Assumption is that bump_version
    # has been run and this contains the correct version number.
    version = run_cmd('cat include/mbedtls/version.h | \
        clang -Iinclude -dM -E - | grep "MBEDTLS_VERSION_STRING "')
    version = version.split()[-1][1:-1]

    # Get main changelog content.
    assemble_path = os.path.join(os.getcwd(), 'scripts', 'assemble_changelog.py')
    with tempfile.NamedTemporaryFile() as temp_file:
        run_cmd(f'{assemble_path} -o {temp_file.name} --latest-only')
        with open(temp_file.name) as f:
            changelog = f.read()

    arg_hash = {
        'version': version,
        'tarhash': '',
        'ziphash': '',
        'changelog': changelog.strip(),
        'description': args.description.strip(),
        'whoshouldupdate': args.who.strip()
    }

    spellcheck(generate_content(arg_hash))

    arg_hash['tarhash'] = sha256_digest(args.tar) if args.tar else "x" * 64
    arg_hash['ziphash'] = sha256_digest(args.zip) if args.zip else "x" * 64
    return generate_content(arg_hash)


def main():
    # Very basic check to see if we are in the root.
    path = os.path.join(os.getcwd(), 'scripts', 'generate_release_notes.py')
    if not os.path.exists(path):
        error(f'{sys.argv[0]} must be run from the mbedtls root')

    args = parse_args(sys.argv[1:])

    content = gen_rel_notes(args)
    with open(args.output, 'w') as f:
        f.write(content)

    print(CHECKLIST)


if __name__ == '__main__':
    main()
