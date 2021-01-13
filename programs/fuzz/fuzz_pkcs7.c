#include <stdint.h>
#include "mbedtls/pkcs7.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
#ifdef MBEDTLS_PKCS7_C
    mbedtls_pkcs7 pkcs7;

    mbedtls_pkcs7_init( &pkcs7 );

    mbedtls_pkcs7_parse_der( Data, Size, &pkcs7 );

    mbedtls_pkcs7_free( &pkcs7 );
#else
    (void) Data;
    (void) Size;
#endif

    return 0;
}
