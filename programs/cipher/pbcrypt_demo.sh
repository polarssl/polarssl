#!/bin/sh
set -e -u

# depends_on:MBEDTLS_CIPHER_C:MBEDTLS_CTR_DRBG_C:MBEDTLS_ENTROPY_C:MBEDTLS_FS_IO:MBEDTLS_MD_C:MBEDTLS_PKCS12_C

program="${0%/*}"/pbcrypt
plaintext_file=sample-text.txt
decrypted_file=sample-text.decrypted
bad_decrypted_file=sample-text.bad
ciphertext_file=sample-text.pbcrypt
again_ciphertext_file=sample-text-again.pbcrypt
corrupted_ciphertext_file=sample-text-corrupted.pbcrypt
password1=swordfish
password2=sturgeon

# Like '!', but stop on failure with 'set -e'
not () {
  if "$@"; then false; fi
}

run () {
  echo
  echo "$1"
  shift
  echo "+ $*"
  "$@"
}

run_bad () {
  echo
  echo "$1 This must fail."
  shift
  echo "+ ! $*"
  not "$@"
}

cleanup () {
  rm -f "$plaintext_file" "$decrypted_file" "$bad_decrypted_file"
  rm -f "$ciphertext_file" "$again_ciphertext_file" "$corrupted_ciphertext_file"
}
trap 'cleanup; trap - HUP; kill -HUP $$' HUP
trap 'cleanup; trap - INT; kill -INT $$' INT
trap 'cleanup; trap - TERM; kill -TERM $$' TERM

echo 'Create a sample file.'
if [ ! -e "$plaintext_file" ]; then
  cat <<EOF >"$plaintext_file"
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod
tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim
veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea
commodo consequat. Duis aute irure dolor in reprehenderit in voluptate
velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint
occaecat cupidatat non proident, sunt in culpa qui officia deserunt
mollit anim id est laborum.
EOF
fi

run 'Encrypt the sample file.' \
    "$program" encrypt password="$password1" input="$plaintext_file" output="$ciphertext_file"

run 'Encrypt again with the same password.' \
    "$program" encrypt password="$password1" input="$plaintext_file" output="$again_ciphertext_file"

echo 'Since the encryption is randomized, the two encrypted files must differ.'
not cmp "$ciphertext_file" "$again_ciphertext_file"

run 'Decrypt the file with the correct password.' \
    "$program" decrypt password="$password1" input="$ciphertext_file" output="$decrypted_file"

echo 'The decrypted file must be identical to the original.'
cmp "$plaintext_file" "$decrypted_file"

rm -f "$bad_decrypted_file"
run_bad 'Attempt to decrypt the file with an invalid password.' \
        "$program" decrypt password="$password2" input="$ciphertext_file" output="$bad_decrypted_file"
[ ! -e "$bad_decrypted_file" ]

cat "$ciphertext_file" >"$corrupted_ciphertext_file"
echo oopsoops | dd conv=notrunc ibs=1 obs=1 seek=100 of="$corrupted_ciphertext_file"
rm -f "$bad_decrypted_file"
run_bad 'Attempt to decrypt a corrupted file with the correct password.' \
        "$program" decrypt password="$password1" input="$corrupted_ciphertext_file" output="$bad_decrypted_file"
[ ! -e "$bad_decrypted_file" ]

echo
echo 'SUCCESS!'
cleanup
