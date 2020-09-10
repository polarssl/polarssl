
#ifndef MBEDTLS_X509_INVASIVE_H
#define MBEDTLS_X509_INVASIVE_H

#if defined(MBEDTLS_TEST_HOOKS)

/*
 * parse ipv4 address from canonical string form into bytes.
 * return 0 if success, -1 otherwise
 */
int x509_parse_ipv4( const char *h, unsigned char *addr );

/*
 * parse ipv6 address from canonical string form into bytes.
 * return 0 if success, -1 otherwise
 */
int x509_parse_ipv6( const char *h, size_t hlen, unsigned char *addr );
#endif

#endif //MBED_TLS_X509_INVASIVE_H
