"""Knowledge about cryptographic mechanisms implemented in Mbed TLS.

This module is entirely based on the PSA API.
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

import enum
import re
from typing import Iterable, Optional, Tuple

from mbedtls_dev.asymmetric_key_data import ASYMMETRIC_KEY_DATA


BLOCK_CIPHERS = frozenset(['AES', 'ARIA', 'CAMELLIA', 'DES'])
BLOCK_MAC_MODES = frozenset(['CBC_MAC', 'CMAC'])
BLOCK_CIPHER_MODES = frozenset([
    'CTR', 'CFB', 'OFB', 'XTS',
    'ECB_NO_PADDING', 'CBC_NO_PADDING', 'CBC_PKCS7',
])
BLOCK_AEAD_MODES = frozenset(['CCM', 'GCM'])

class EllipticCurveCategory(enum.Enum):
    """Categorization of elliptic curve families.

    The category of a curve determines what algorithms are defined over it.
    """

    SHORT_WEIERSTRASS = 0
    MONTGOMERY = 1
    TWISTED_EDWARDS = 2

    @staticmethod
    def from_family(family: str) -> 'EllipticCurveCategory':
        if family == 'PSA_ECC_FAMILY_MONTGOMERY':
            return EllipticCurveCategory.MONTGOMERY
        if family == 'PSA_ECC_FAMILY_TWISTED_EDWARDS':
            return EllipticCurveCategory.TWISTED_EDWARDS
        # Default to SW, which most curves belong to.
        return EllipticCurveCategory.SHORT_WEIERSTRASS


class KeyType:
    """Knowledge about a PSA key type."""

    def __init__(self, name: str, params: Optional[Iterable[str]] = None) -> None:
        """Analyze a key type.

        The key type must be specified in PSA syntax. In its simplest form,
        `name` is a string 'PSA_KEY_TYPE_xxx' which is the name of a PSA key
        type macro. For key types that take arguments, the arguments can
        be passed either through the optional argument `params` or by
        passing an expression of the form 'PSA_KEY_TYPE_xxx(param1, ...)'
        in `name` as a string.
        """

        self.name = name.strip()
        """The key type macro name (``PSA_KEY_TYPE_xxx``).

        For key types constructed from a macro with arguments, this is the
        name of the macro, and the arguments are in `self.params`.
        """
        if params is None:
            if '(' in self.name:
                m = re.match(r'(\w+)\s*\((.*)\)\Z', self.name)
                assert m is not None
                self.name = m.group(1)
                params = m.group(2).split(',')
        self.params = (None if params is None else
                       [param.strip() for param in params])
        """The parameters of the key type, if there are any.

        None if the key type is a macro without arguments.
        """
        assert re.match(r'PSA_KEY_TYPE_\w+\Z', self.name)

        self.expression = self.name
        """A C expression whose value is the key type encoding."""
        if self.params is not None:
            self.expression += '(' + ', '.join(self.params) + ')'

        m = re.match(r'PSA_KEY_TYPE_(\w+)', self.name)
        assert m
        self.head = re.sub(r'_(?:PUBLIC_KEY|KEY_PAIR)\Z', r'', m.group(1))
        """The key type macro name, with common prefixes and suffixes stripped."""

        self.private_type = re.sub(r'_PUBLIC_KEY\Z', r'_KEY_PAIR', self.name)
        """The key type macro name for the corresponding key pair type.

        For everything other than a public key type, this is the same as
        `self.name`.
        """

    def is_public(self) -> bool:
        """Whether the key type is for public keys."""
        return self.name.endswith('_PUBLIC_KEY')

    ECC_KEY_SIZES = {
        'PSA_ECC_FAMILY_SECP_K1': (192, 224, 256),
        'PSA_ECC_FAMILY_SECP_R1': (225, 256, 384, 521),
        'PSA_ECC_FAMILY_SECP_R2': (160,),
        'PSA_ECC_FAMILY_SECT_K1': (163, 233, 239, 283, 409, 571),
        'PSA_ECC_FAMILY_SECT_R1': (163, 233, 283, 409, 571),
        'PSA_ECC_FAMILY_SECT_R2': (163,),
        'PSA_ECC_FAMILY_BRAINPOOL_P_R1': (160, 192, 224, 256, 320, 384, 512),
        'PSA_ECC_FAMILY_MONTGOMERY': (255, 448),
        'PSA_ECC_FAMILY_TWISTED_EDWARDS': (255, 448),
    }
    KEY_TYPE_SIZES = {
        'PSA_KEY_TYPE_AES': (128, 192, 256), # exhaustive
        'PSA_KEY_TYPE_ARC4': (8, 128, 2048), # extremes + sensible
        'PSA_KEY_TYPE_ARIA': (128, 192, 256), # exhaustive
        'PSA_KEY_TYPE_CAMELLIA': (128, 192, 256), # exhaustive
        'PSA_KEY_TYPE_CHACHA20': (256,), # exhaustive
        'PSA_KEY_TYPE_DERIVE': (120, 128), # sample
        'PSA_KEY_TYPE_DES': (64, 128, 192), # exhaustive
        'PSA_KEY_TYPE_HMAC': (128, 160, 224, 256, 384, 512), # standard size for each supported hash
        'PSA_KEY_TYPE_RAW_DATA': (8, 40, 128), # sample
        'PSA_KEY_TYPE_RSA_KEY_PAIR': (1024, 1536), # small sample
    }
    def sizes_to_test(self) -> Tuple[int, ...]:
        """Return a tuple of key sizes to test.

        For key types that only allow a single size, or only a small set of
        sizes, these are all the possible sizes. For key types that allow a
        wide range of sizes, these are a representative sample of sizes,
        excluding large sizes for which a typical resource-constrained platform
        may run out of memory.
        """
        if self.private_type == 'PSA_KEY_TYPE_ECC_KEY_PAIR':
            assert self.params is not None
            return self.ECC_KEY_SIZES[self.params[0]]
        return self.KEY_TYPE_SIZES[self.private_type]

    # "48657265006973206b6579a064617461"
    DATA_BLOCK = b'Here\000is key\240data'
    def key_material(self, bits: int) -> bytes:
        """Return a byte string containing suitable key material with the given bit length.

        Use the PSA export representation. The resulting byte string is one that
        can be obtained with the following code:
        ```
        psa_set_key_type(&attributes, `self.expression`);
        psa_set_key_bits(&attributes, `bits`);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
        psa_generate_key(&attributes, &id);
        psa_export_key(id, `material`, ...);
        ```
        """
        if self.expression in ASYMMETRIC_KEY_DATA:
            if bits not in ASYMMETRIC_KEY_DATA[self.expression]:
                raise ValueError('No key data for {}-bit {}'
                                 .format(bits, self.expression))
            return ASYMMETRIC_KEY_DATA[self.expression][bits]
        if bits % 8 != 0:
            raise ValueError('Non-integer number of bytes: {} bits for {}'
                             .format(bits, self.expression))
        length = bits // 8
        if self.name == 'PSA_KEY_TYPE_DES':
            # "644573206b457901644573206b457902644573206b457904"
            des3 = b'dEs kEy\001dEs kEy\002dEs kEy\004'
            return des3[:length]
        return b''.join([self.DATA_BLOCK] * (length // len(self.DATA_BLOCK)) +
                        [self.DATA_BLOCK[:length % len(self.DATA_BLOCK)]])

    def can_do(self, alg: 'Algorithm') -> bool:
        """Whether this key type can be used for operations with the given algorithm."""
        #pylint: disable=too-many-return-statements
        if alg.is_wildcard:
            return False
        if self.head == 'HMAC' and alg.head == 'HMAC':
            return True
        if self.head in BLOCK_CIPHERS and \
           alg.head in frozenset.union(BLOCK_MAC_MODES,
                                       BLOCK_CIPHER_MODES,
                                       BLOCK_AEAD_MODES):
            return True
        if self.head == 'CHACHA20' and alg.head == 'CHACHA20_POLY1305':
            return True
        if self.head in {'ARC4', 'CHACHA20'} and \
           alg.head == 'STREAM_CIPHER':
            return True
        if self.head == 'RSA' and alg.head.startswith('RSA_'):
            return True
        if self.head == 'ECC':
            assert self.params is not None
            eccc = EllipticCurveCategory.from_family(self.params[0])
            if alg.head == 'ECDH' and \
               eccc in {EllipticCurveCategory.SHORT_WEIERSTRASS,
                        EllipticCurveCategory.MONTGOMERY}:
                return True
            if alg.head == 'ECDSA' and \
               eccc == EllipticCurveCategory.SHORT_WEIERSTRASS:
                return True
            if alg.head in {'PURE_EDDSA', 'EDDSA_PREHASH'} and \
               eccc == EllipticCurveCategory.TWISTED_EDWARDS:
                return True
        return False


class AlgorithmCategory(enum.Enum):
    """PSA algorithm categories."""
    # The numbers are aligned with the category bits in numerical values of
    # algorithms.
    HASH = 2
    MAC = 3
    CIPHER = 4
    AEAD = 5
    SIGN = 6
    ASYMMETRIC_ENCRYPTION = 7
    KEY_DERIVATION = 8
    KEY_AGREEMENT = 9

    def requires_key(self) -> bool:
        """Whether operations in this category are set up with a key."""
        return self not in {self.HASH, self.KEY_DERIVATION}

    def is_asymmetric(self) -> bool:
        """Whether operations in this category involve asymmetric keys."""
        return self in {
            self.SIGN,
            self.ASYMMETRIC_ENCRYPTION,
            self.KEY_AGREEMENT
        }


class AlgorithmNotRecognized(Exception):
    def __init__(self, expr: str) -> None:
        super().__init__('Algorithm not recognized: ' + expr)
        self.expr = expr


class Algorithm:
    """Knowledge about a PSA algorithm."""

    @staticmethod
    def determine_base(expr: str) -> str:
        """Return an expression for the "base" of the algorithm.

        This strips off variants of algorithms such as MAC truncation.

        This function does not attempt to detect invalid inputs.
        """
        m = re.match(r'PSA_ALG_(?:'
                     r'(?:TRUNCATED|AT_LEAST_THIS_LENGTH)_MAC|'
                     r'AEAD_WITH_(?:SHORTENED|AT_LEAST_THIS_LENGTH)_TAG'
                     r')\((.*),[^,]+\)\Z', expr)
        if m:
            expr = m.group(1)
        return expr

    @staticmethod
    def determine_head(expr: str) -> str:
        """Return the head of an algorithm expression.

        The head is the first (outermost) constructor, without its PSA_ALG_
        prefix, and with some normalization of similar algorithms.
        """
        m = re.match(r'PSA_ALG_(?:DETERMINISTIC_)?(\w+)', expr)
        if not m:
            raise AlgorithmNotRecognized(expr)
        head = m.group(1)
        if head == 'KEY_AGREEMENT':
            m = re.match(r'PSA_ALG_KEY_AGREEMENT\s*\(\s*PSA_ALG_(\w+)', expr)
            if not m:
                raise AlgorithmNotRecognized(expr)
            head = m.group(1)
        head = re.sub(r'_ANY\Z', r'', head)
        if re.match(r'ED[0-9]+PH\Z', head):
            head = 'EDDSA_PREHASH'
        return head

    @staticmethod
    def determine_category(expr: str, head: str) -> AlgorithmCategory:
        """Return the category of the given algorithm expression.

        This function does not attempt to detect invalid inputs.
        """
        #pylint: disable=too-many-return-statements
        if head.startswith('SHA') or \
           head.startswith('MD') or \
           head.startswith('RIPEMD') or \
           head == 'ANY_HASH':
            return AlgorithmCategory.HASH
        if head in 'HMAC':
            return AlgorithmCategory.MAC
        if head in BLOCK_MAC_MODES:
            return AlgorithmCategory.MAC
        if head in BLOCK_CIPHER_MODES:
            return AlgorithmCategory.CIPHER
        if head == 'STREAM_CIPHER':
            return AlgorithmCategory.CIPHER
        if head in BLOCK_AEAD_MODES:
            return AlgorithmCategory.AEAD
        if head == 'CHACHA20_POLY1305':
            return AlgorithmCategory.AEAD
        if head in {'DSA', 'ECDSA', 'PURE_EDDSA', 'EDDSA_PREHASH',
                    'RSA_PKCS1V15_SIGN', 'RSA_PKCS1V15_SIGN_RAW', 'RSA_PSS'}:
            return AlgorithmCategory.SIGN
        if head in {'RSA_PKCS1V15_CRYPT', 'RSA_OAEP'}:
            return AlgorithmCategory.ASYMMETRIC_ENCRYPTION
        if head in {'HKDF', 'TLS12_PRF', 'TLS12_PSK_TO_MS'}:
            return AlgorithmCategory.KEY_DERIVATION
        if head in {'ECDH', 'FFDH', 'KEY_AGREEMENT'}:
            return AlgorithmCategory.KEY_AGREEMENT
        raise AlgorithmNotRecognized(expr)

    @staticmethod
    def determine_wildcard(expr) -> bool:
        """Whether the given algorithm expression is a wildcard.

        This function does not attempt to detect invalid inputs.
        """
        if re.search(r'\bPSA_ALG_ANY_HASH\b', expr):
            return True
        if re.search(r'_AT_LEAST_', expr):
            return True
        return False

    def __init__(self, expr: str) -> None:
        """Analyze an algorithm value.

        The algorithm must be expressed as a C expression containing only
        calls to PSA algorithm constructor macros and numeric literals.

        This class is only programmed to handle valid expressions. Invalid
        expressions may result in exceptions or in nonsensical results.
        """
        self.expression = re.sub(r'\s+', r'', expr)
        self.base_expression = self.determine_base(self.expression)
        self.head = self.determine_head(self.base_expression)
        self.category = self.determine_category(self.base_expression, self.head)
        self.is_wildcard = self.determine_wildcard(self.expression)

    def is_key_agreement_with_derivation(self) -> bool:
        """Whether this is a combined key agreement and key derivation algorithm."""
        if self.category != AlgorithmCategory.KEY_AGREEMENT:
            return False
        m = re.match(r'PSA_ALG_KEY_AGREEMENT\(\w+,\s*(.*)\)\Z', self.expression)
        if not m:
            return False
        kdf_alg = m.group(1)
        # Assume kdf_alg is either a valid KDF or 0.
        return not re.match(r'(?:0[Xx])?0+\s*\Z', kdf_alg)

    def can_do(self, category: AlgorithmCategory) -> bool:
        """Whether this algorithm fits the specified operation category."""
        if category == self.category:
            return True
        if category == AlgorithmCategory.KEY_DERIVATION and \
           self.is_key_agreement_with_derivation():
            return True
        return False
