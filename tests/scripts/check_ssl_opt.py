#!/usr/bin/env python3
"""
Check some requires_xxx in ssl-opt.sh.

Usage: check_ssl_opt.py [PATH/TO/ssl-opt.sh]
"""

import os
import re
import subprocess
import sys
import tempfile
from typing import Callable, Optional, Pattern, Iterator, TypeVar

T = TypeVar('T') #pylint: disable=invalid-name

SOURCE_BLOCKS = (
    (re.compile(r'run_tests?_\w+ *\(\)'), re.compile(r'}')),
    (re.compile(r'(requires|run)_\w+ (?! *\()'), re.compile(r'\n'))
)

def transform_file(inp, out) -> None:
    """Transform ssl-opt.sh into a script that just dumps data about test cases. """
    copy_until = None #type: Optional[Pattern]
    for line in inp:
        if not copy_until:
            for (from_re, until_re) in SOURCE_BLOCKS:
                if from_re.match(line):
                    copy_until = until_re
                    break
        if copy_until:
            line = re.sub(r'\A( *)requires_', r'\1requires ', line)
            out.write(line)
            if copy_until.match(line):
                copy_until = None
        else:
            out.write('\n')

def run_adapted_file(filename: str) -> str:
    cmd = [os.path.join(os.path.dirname(__file__),
                        'run-ssl-opt-for-check.sh'),
           filename]
    #pylint: disable=try-except-raise
    try:
        return subprocess.check_output(cmd).decode('ascii')
    except subprocess.CalledProcessError:
        #import pdb; pdb.set_trace()
        raise

class Test:
    """Information about one test case of ssl-opt.sh."""

    def __init__(self, data: str) -> None:
        parts = data.split('\036')
        (self.description, requirements,
         self.server, self.proxy, self.client, self.ret,
         self.options) = parts
        self.requirements = frozenset(requirements.split(';'))

    def requires_option(self, symbol: str) -> bool:
        return 'config_enabled ' + symbol in self.requirements

    @staticmethod
    def is_mbedtls(cmd: str) -> bool:
        return cmd.startswith('ssl_client2') or cmd.startswith('ssl_server2')

    def get_mbedtls_runtime_option(self, cmd: str, name: str) -> Optional[str]:
        """Look for an option passed on an mbedtls utility command line."""
        if not self.is_mbedtls(cmd):
            return None
        m = re.search(r' ' + name + '=([^ ]*)', cmd)
        if m:
            return m.group(1)
        else:
            return None

    def enables_option(self, name: str) -> bool:
        """True if the client or server is Mbed TLS and has name=... with a nonzero value."""
        for cmd in (self.client, self.server):
            value = self.get_mbedtls_runtime_option(cmd, name)
            if value is not None and value != '0':
                return True
        return False

    def max_option(self,
                   name: str,
                   func: Callable[[Optional[str]], T]) -> T:
        """Maximum value of the specified option between the client and the server.

        Call ``func(value)`` on each option value. ``value`` is ``None`` if
        the option was not passed.
        """
        return max(func(self.get_mbedtls_runtime_option(cmd, name))
                   for cmd in (self.client, self.server))

    def match_options(self, symbol: str, *opts: str) -> Iterator[str]:
        """Match compile-time configuration with command line

        Check that the compile-time configuration symbol is required iff
        the command-line option opt is used with a nonzero value.
        """
        requires = self.requires_option(symbol)
        enables = any(self.enables_option(opt) for opt in opts)
        if requires and not enables:
            yield 'Configuration {} is required but not used'.format(symbol)
        if not requires and enables:
            yield 'Configuration {} is used but not required'.format(symbol)

    # This list is deliberately partial and the lengths are not exact.
    # The objective is to match the highly simplified declared requirements
    # in ssl-opt.sh rather than the truth.
    MAX_CONTENT_LEN_FOR_CRT_FILE = {
        'data_files/server7_int-ca.crt': 2048,
    }

    def max_content_len_for_crt_file(self, filename: Optional[str]) -> int:
        if filename is None:
            return 0
        return self.MAX_CONTENT_LEN_FOR_CRT_FILE.get(filename, 0)

    def max_content_len(self) -> Iterator[str]:
        """Check the plausibility of requires_max_content_len (or lack thereof)."""
        max_frag_len = self.max_option('max_frag_len',
                                       lambda x: 0 if x is None else int(x))
        mtu = self.max_option('mtu', lambda x: 0 if x is None else int(x))
        cert = self.max_option('crt_file', self.max_content_len_for_crt_file)
        required = 0
        for req in self.requirements:
            m = re.match(r'max_content_len (\w+)', req)
            if m:
                required = max(required, int(m.group(1)))
        if not required:
            if max_frag_len:
                yield ('max_frag_len={} but no requires_max_content_len'
                       .format(max_frag_len))
            if mtu:
                pass #yield 'mtu={} but no requires_max_content_len'.format(mtu)
            if cert:
                pass #yield 'cert length up to {} but no requires_max_content_len'.format(cert)
            return
        if not (max_frag_len or mtu or cert):
            yield ('requires_max_content_len {} for no discernible reason'
                   .format(required))
        if max(max_frag_len, mtu, cert) not in (required, required - 1):
            yield ('requires_max_content_len {} but max_frag_len={}, mtu={}'
                   .format(required, max_frag_len, mtu))

    def problems(self) -> Iterator[str]:
        """Perform all checks. Iterate over the problems encountered."""
        yield from self.match_options('MBEDTLS_SSL_DTLS_CONNECTION_ID',
                                      'cid', 'cid_renego')
        yield from self.match_options('MBEDTLS_SSL_CONTEXT_SERIALIZATION',
                                      'serialize')
        yield from self.match_options('MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK',
                                      'ca_callback')
        yield from self.max_content_len()

def analyze_output(output: str) -> bool:
    """Analyze the output of run-ssl-opt-for-check.

    Return False if there are problems.
    """
    ok = True
    for part in output.split('\035'):
        if not part:
            continue
        test = Test(part)
        for problem in test.problems():
            ok = False
            print(test.description + ';' + problem)
    return ok

def check_ssl_opt(original_file_name: str) -> bool:
    """Analyze the test cases in ssl-opt.sh for missing or spurious requirements."""
    dirname = os.path.dirname(os.path.abspath(original_file_name))
    basename = os.path.basename(original_file_name)
    with tempfile.NamedTemporaryFile(
            prefix=os.path.join(dirname, basename + '-check-'), suffix='.sh',
            mode='tw', newline='\n'
    ) as transformed_file:
        with open(original_file_name) as original_file:
            transform_file(original_file, transformed_file)
            transformed_file.flush()
        output = run_adapted_file(transformed_file.name)
    return analyze_output(output)

if __name__ == '__main__':
    sys.exit(not check_ssl_opt(
        sys.argv[1] if len(sys.argv) > 1 else
        os.path.join(os.path.dirname(__file__), os.path.pardir, 'ssl-opt.sh')
    ))
