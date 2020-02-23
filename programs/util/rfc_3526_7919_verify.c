/*
 *  Program verifying construction and safety properties
 *  of primes standardized in RFC 3526 and RFC 7919.
 *
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_DHM_C)
#include "mbedtls/bignum.h"
#include "mbedtls/error.h"
#include "mbedtls/dhm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <string.h>
#endif

typedef enum {
    DHM_PRIMES_RFC_3526 = 0,
    DHM_PRIMES_RFC_7919
} dhm_primes_stds_t;

typedef enum {
    check_full = 0,
    check_primality,
    check_formula,
    check_canonicity
} check_t;

typedef struct
{
    dhm_primes_stds_t std;
    unsigned          bitsize;
    check_t           check;
    unsigned          stepsize;
    unsigned          thread;
} options_t;
options_t opt;

#define DFL_RFC        DHM_PRIMES_RFC_3526
#define DFL_BITSIZE    2048
#define DFL_CHECK      check_full
#define DFL_STEP       1
#define DFL_THREAD     0

#define USAGE \
    "\n usage: rfc_3526_7919_verify param=<>...\n"                                        \
    "\n This program verifies the generation procedure for primes"                        \
    " standardized in RFC 3526 and 7919\n"                                                \
    "\n The primes from RFC 3526 and RFC 7919 have been generating by the"                \
    " following trust-worthy procedure:"                                                  \
    "\n (1) Fix N in { 2048, 3072, 4096, 6144, 8192 } and consider the N-bit number"      \
    " the first and last 64 bits are all 1, and the remaining N - 128 bits of"            \
    " which are 0x7ff...ff."                                                              \
    "\n (2) Add the smallest multiple of the first N - 129 bits of the binary expansion"  \
    " of pi (for RFC 5236) or e (for RFC 7919) to this intermediate bit-string"           \
    " such that the resulting integer is a safe-prime."                                   \
    "\n (3) The result is the respective RFC 3526 / 7919 prime, and the corresponding"    \
    " generator is always chosen to be 2 (which is a square for these prime,"             \
    " hence the corresponding subgroup has order (p-1)/2 and avoids leaking a"            \
    " bit in the private exponent).\n"                                                    \
    "\n For RFC 7919 this procedure is described in Appendix A of RFC 7919,"              \
    " while for RFC 3526 the minimality property of step (2) is not explicitly mentioned,"\
    " albeit true.\n"                                                                     \
    "\n acceptable parameters:\n"                                                         \
    "    rfc=3526|7919 default: 3526\n"                                                   \
    "    bitsize=2048|3072|4096|6144|8192 default: 2048\n"                                \
    "    check=full|primality|formula|canonicity default:full\n"                          \
    "      * primality checks whether hardcoded number is safe prime\n"                   \
    "      * formula checks hardcoded number against formula in RFC\n"                    \
    "      * canonicity checks minimality of offset for safe primality\n"                 \
    "        (this is an very computation-heavy task, especially for\n"                   \
    "         high bit-sizes)\n"                                                          \
    "      * full checks all of the above\n"                                              \
    "    stepsize=%%d (max 128) default:1\n"                                              \
    "    thread=%%d (between 0 and stepsize-1) default:0\n"                               \
    "      stepsize and thread can be used to have multiple processes\n"                  \
    "      share the computational load of the canonicity checks.\n"                      \
    "      with stepsize=N and thread=i, only offsets congruent i\n"                      \
    "      modulo N will be checked for.\n"                                               \
    "\n\n available primes:\n"                                                            \
    "    RFC 3526: 2048-bit, 3072-bit, 4096-bit\n"                                        \
    "    RFC 7919: 2048-bit, 3072-bit, 4096-bit, 6144-bit, 8192-bit\n"                    \
    "\n"

/* To generate from decimal expansions easily found on the web, use e.g.
 * > echo "obase=16;ibase=10;2^9000 * 2.7182818284590452353..." | bc
 */
static char const e_hex[] =
    "2"
    "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF324"
    "E7738926CFBE5F4BF8D8D8C31D763DA06C80ABB1185EB4F7C7B5757F5958490CFD47"
    "D7C19BB42158D9554F7B46BCED55C4D79FD5F24D6613C31C3839A2DDF8A9A276BCFB"
    "FA1C877C56284DAB79CD4C2B3293D20E9E5EAF02AC60ACC93ED874422A52ECB238FE"
    "EE5AB6ADD835FD1A0753D0A8F78E537D2B95BB79D8DCAEC642C1E9F23B829B5C2780"
    "BF38737DF8BB300D01334A0D0BD8645CBFA73A6160FFE393C48CBBBCA060F0FF8EC6"
    "D31BEB5CCEED7F2F0BB088017163BC60DF45A0ECB1BCD289B06CBBFEA21AD08E1847"
    "F3F7378D56CED94640D6EF0D3D37BE67008E186D1BF275B9B241DEB64749A47DFDFB"
    "96632C3EB061B6472BBF84C26144E49C2D04C324EF10DE513D3F5114B8B5D374D93C"
    "B8879C7D52FFD72BA0AAE7277DA7BA1B4AF1488D8E836AF14865E6C37AB6876FE690"
    "B571121382AF341AFE94F77BCF06C83B8FF5675F0979074AD9A787BC5B9BD4B0C593"
    "7D3EDE4C3A79396215EDAB1F57D0B5A7DB461DD8F3C75540D00121FD56E95F8C731E"
    "9C4D7221BBED0C62BB5A87804B679A0CAA41D802A4604C311B71DE3E5C6B400E024A"
    "6668CCF2E2DE86876E4F5C50000F0A93B3AA7E6342B302A0A47373B25F73E3B26D56"
    "9FE2291AD36D6A147D1060B871A2801F9783764082FF592D9140DB1E9399DF4B0E14"
    "CA8E88EE9110B2BD4FA98EED150CA6DD8932245EF7592C703F532CE3A30CD31C070E"
    "B36B4195FF33FB1C66C7D70F93918107CE2051FED33F6D1DE9491C7DEA6A5A442E15"
    "4C8BB6D8D0362803BC248D414478C2AFB07FFE78E89B9FECA7E3060C08F0D61F8E36"
    "801DF66D1D8F9392E52CAEF0653199479DF2BE64BBAAB008CA8A06FDACE9CE704898"
    "45A082BA36D611E99F2FBE724246D18B54E335CAC0DD1AB9DFD7988A4B0C4558AA11"
    "9417720B6E150CE2B927D48D7256E445E333CB7572B3BD00FB2746043189CAC116CE"
    "DC7E771AE0358FF752A3A6B6C79A58A9A549B50C5870690755C35E4E36B529038CA7"
    "33FD1AAA8DAB40133D80320E0790968C76546B993F6C8FF3B2542750DA1FFADA7B74"
    "731782E330EF7D92C43BE1AD8C50A8EAE20A5556CBDD1F24C99972CB03C73006F5C0"
    "8A4E220E74ABC179151412B1E2DD60A08A11B02E8D70D7D71645833011BF60945507"
    "F1A32721AC08AEDC2661DA91839D146A2A4C425C0FFB87085F9B0E09B94B146A9A47"
    "83908F3F267A78C59430485ED89205B36B66A57E756E006522367028287F8C1D695D"
    "F88C60FE07528FCBE915C7BF23382EA293FA2DA1577F9CAC299BB7B4BEEAFEF9628C"
    "3EBEAF87175C6A1F8BDD07BE307FA1BFA9AEFF794C19DFC365F447527DEA110F4208"
    "B941AA7D185380478AA520E3FE2335A322EDF147BBDB527AA2AD3CB0F7D6ED381CD6"
    "AC35A1D24BF89B75019605AEE9DFABA5CFCED033BA2102A0BDBE3B49D7272F89E09D"
    "008E5D5BD99239362861EB426297C5841397515473CF2A3D6DE58C4BB1B91AD97ABF"
    "028E9665DA4ECE80DDC13E0DF4322EDA0FD389B175E8D10D08C5230A6B576C94FC52"
    "B4E74B";

/* To generate from decimal expansions easily found on the web, use e.g.
 * > echo "obase=16;ibase=10;2^9000 * 3.141592653589793238462..." | bc
 */
static char const pi_hex[] =
    "3"
    "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
    "452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B5470917"
    "9216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96"
    "BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69"
    "A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5"
    "9C30D5392AF26013C5D1B023286085F0CA417918B8DB38EF8E79DCB0603A180E"
    "6C9E0E8BB01E8A3ED71577C1BD314B2778AF2FDA55605C60E65525F3AA55AB94"
    "5748986263E8144055CA396A2AAB10B6B4CC5C341141E8CEA15486AF7C72E993"
    "B3EE1411636FBC2A2BA9C55D741831F6CE5C3E169B87931EAFD6BA336C24CF5C"
    "7A325381289586773B8F48986B4BB9AFC4BFE81B6628219361D809CCFB21A991"
    "487CAC605DEC8032EF845D5DE98575B1DC262302EB651B8823893E81D396ACC5"
    "0F6D6FF383F442392E0B4482A484200469C8F04A9E1F9B5E21C66842F6E96C9A"
    "670C9C61ABD388F06A51A0D2D8542F68960FA728AB5133A36EEF0B6C137A3BE4"
    "BA3BF0507EFB2A98A1F1651D39AF017666CA593E82430E888CEE8619456F9FB4"
    "7D84A5C33B8B5EBEE06F75D885C12073401A449F56C16AA64ED3AA62363F7706"
    "1BFEDF72429B023D37D0D724D00A1248DB0FEAD349F1C09B075372C980991B7B"
    "25D479D8F6E8DEF7E3FE501AB6794C3B976CE0BD04C006BAC1A94FB6409F60C4"
    "5E5C9EC2196A246368FB6FAF3E6C53B51339B2EB3B52EC6F6DFC511F9B30952C"
    "CC814544AF5EBD09BEE3D004DE334AFD660F2807192E4BB3C0CBA85745C8740F"
    "D20B5F39B9D3FBDB5579C0BD1A60320AD6A100C6402C7279679F25FEFB1FA3CC"
    "8EA5E9F8DB3222F83C7516DFFD616B152F501EC8AD0552AB323DB5FAFD238760"
    "53317B483E00DF829E5C57BBCA6F8CA01A87562EDF1769DBD542A8F6287EFFC3"
    "AC6732C68C4F5573695B27B0BBCA58C8E1FFA35DB8F011A010FA3D98FD2183B8"
    "4AFCB56C2DD1D35B9A53E479B6F84565D28E49BC4BFB9790E1DDF2DAA4CB7E33"
    "62FB1341CEE4C6E8EF20CADA36774C01D07E9EFE2BF11FB495DBDA4DAE909198"
    "EAAD8E716B93D5A0D08ED1D0AFC725E08E3C5B2F8E7594B78FF6E2FBF2122B64"
    "8888B812900DF01C4FAD5EA0688FC31CD1CFF191B3A8C1AD2F2F2218BE0E1777"
    "EA752DFE8B021FA1E5A0CC0FB56F74E818ACF3D6CE89E299B4A84FE0FD13E0B7"
    "7CC43B81D2ADA8D9165FA2668095770593CC7314211A1477E6AD206577B5FA86"
    "C75442F5FB9D35CFEBCDAF0C7B3E89A0D6411BD3AE1E7E4900250E2D2071B35E"
    "226800BB57B8E0AF2464369BF009B91E5563911D59DFA6AA78C14389D95A537F"
    "207D5BA202E5B9C5832603766295CFA911C819684E734A41B3472DCA7B14A94A"
    "1B5100529A532915D60F573FBC9BC6E42B60A47681E6740008BA6FB5571BE91F"
    "F296EC6B2A0DD915B6636521E7B9F9B6FF34052EC585566453B02D5DA99F8FA1"
    "08BA47996E85076A4B7A70E9B5B32944DB75092EC4192623AD6EA6B049A7DF7D"
    "9CEE60B88FEDB266ECAA8C71699A17FF5664526CC2B19EE1193602A575094C29"
    "A0591340E4183A3E3F54989A5B429D656B8FE4D699F73FD6A1D29C07EFE830F5"
    "4D2D38E6F0255DC14CDD20868470EB266382E9C6021ECC5E09686B3F3EBAEFC9";

typedef struct
{
    dhm_primes_stds_t std;
    unsigned bitsize;
    unsigned offset;  /* Offset from the canonical base
                         in multiples of 2^64 */
    const unsigned char * ref; /* Hardcoded prime        */
    const char * ref_str;      /* Hardcoded prime in hex */
} test_vector_t;

const unsigned char mbedtls_dhm_rfc3526_modp_2048_p[] =
    MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
const unsigned char mbedtls_dhm_rfc3526_modp_3072_p[] =
    MBEDTLS_DHM_RFC3526_MODP_3072_P_BIN;
const unsigned char mbedtls_dhm_rfc3526_modp_4096_p[] =
    MBEDTLS_DHM_RFC3526_MODP_4096_P_BIN;
const unsigned char mbedtls_dhm_rfc7919_ffdhe2048_p[] =
    MBEDTLS_DHM_RFC7919_FFDHE2048_P_BIN;
const unsigned char mbedtls_dhm_rfc7919_ffdhe3072_p[] =
    MBEDTLS_DHM_RFC7919_FFDHE3072_P_BIN;
const unsigned char mbedtls_dhm_rfc7919_ffdhe4096_p[] =
    MBEDTLS_DHM_RFC7919_FFDHE4096_P_BIN;
const unsigned char mbedtls_dhm_rfc7919_ffdhe6144_p[] =
    MBEDTLS_DHM_RFC7919_FFDHE6144_P_BIN;
const unsigned char mbedtls_dhm_rfc7919_ffdhe8192_p[] =
    MBEDTLS_DHM_RFC7919_FFDHE8192_P_BIN;

static test_vector_t const tests[] = {
    { DHM_PRIMES_RFC_3526, 2048, 124476,
      mbedtls_dhm_rfc3526_modp_2048_p,
      MBEDTLS_DHM_RFC3526_MODP_2048_P },
    { DHM_PRIMES_RFC_3526, 3072, 1690314,
      mbedtls_dhm_rfc3526_modp_3072_p,
      MBEDTLS_DHM_RFC3526_MODP_3072_P },
    { DHM_PRIMES_RFC_3526, 4096, 240904,
      mbedtls_dhm_rfc3526_modp_4096_p,
      MBEDTLS_DHM_RFC3526_MODP_4096_P },
    { DHM_PRIMES_RFC_7919, 2048, 560316,   mbedtls_dhm_rfc7919_ffdhe2048_p, NULL },
    { DHM_PRIMES_RFC_7919, 3072, 2625351,  mbedtls_dhm_rfc7919_ffdhe3072_p, NULL },
    { DHM_PRIMES_RFC_7919, 4096, 5736041,  mbedtls_dhm_rfc7919_ffdhe4096_p, NULL },
    { DHM_PRIMES_RFC_7919, 6144, 15705020, mbedtls_dhm_rfc7919_ffdhe6144_p, NULL },
    { DHM_PRIMES_RFC_7919, 8192, 10965728, mbedtls_dhm_rfc7919_ffdhe8192_p, NULL }
};

static const size_t num_tests = sizeof( tests ) / sizeof( *tests );

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_DHM_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    int ret = 0;
    unsigned i;

    int arg_idx;
    char *p, *q;

    test_vector_t const *test;

    size_t max_modifiable_bit;
    size_t nums_len, excess_bits;
    size_t nums_digits;

    const char * nums_constant;

    mbedtls_mpi P, R, B, Bp, NUMS, S, Sp;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    /* Initialization */

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    mbedtls_mpi_init( &P    );
    mbedtls_mpi_init( &R    );
    mbedtls_mpi_init( &B    );
    mbedtls_mpi_init( &Bp   );
    mbedtls_mpi_init( &S    );
    mbedtls_mpi_init( &Sp   );
    mbedtls_mpi_init( &NUMS );

    /* Process command line */

    if( argc == 0 )
    {
    usage:
        mbedtls_printf( USAGE );
        goto cleanup;
    }

    opt.std      = DFL_RFC;
    opt.bitsize  = DFL_BITSIZE;
    opt.check    = DFL_CHECK;
    opt.stepsize = DFL_STEP;
    opt.thread   = DFL_THREAD;

    for( arg_idx = 1; arg_idx < argc; arg_idx++ )
    {
        p = argv[arg_idx];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "rfc" ) == 0 )
        {
            if( strcmp( q, "3526" ) == 0 )
                opt.std = DHM_PRIMES_RFC_3526;
            else if( strcmp( q, "7919" ) == 0 )
                opt.std = DHM_PRIMES_RFC_7919;
            else
            {
                mbedtls_printf( " Illegal value for argument 'rfc'\n" );
                goto usage;
            }
        }
        else if( strcmp( p, "bitsize" ) == 0 )
        {
            opt.bitsize = atoi( q );
            if( opt.bitsize != 2048 &&
                opt.bitsize != 3072 &&
                opt.bitsize != 4096 &&
                opt.bitsize != 6144 &&
                opt.bitsize != 8192 )
            {
                mbedtls_printf( " Illegal value for argument 'bitsize'\n" );
                goto usage;
            }
        }
        else if( strcmp( p, "stepsize" ) == 0 )
        {
            opt.stepsize = atoi( q );
            if( opt.stepsize <= 0 || opt.stepsize > 128 )
            {
                mbedtls_printf( " Illegal value for argument 'stepsize'\n" );
                goto usage;
            }
        }
        else if( strcmp( p, "thread" ) == 0 )
        {
            opt.thread = atoi( q );
            if( opt.thread > 128 )
            {
                mbedtls_printf( " Illegal value for argument 'thread'\n" );
                goto usage;
            }
        }
        else if( strcmp( p, "check" ) == 0 )
        {
            if( strcmp( q, "full" ) == 0 )
                opt.check = check_full;
            else if( strcmp( q, "primality" ) == 0 )
                opt.check = check_primality;
            else if( strcmp( q, "formula" ) == 0 )
                opt.check = check_formula;
            else if( strcmp( q, "canonicity" ) == 0 )
                opt.check = check_canonicity;
            else
            {
                mbedtls_printf( " Illegal value for argument 'check'\n" );
                goto usage;
            }
        }
        else
            goto usage;
    }

    if( opt.thread >= opt.stepsize )
        goto usage;

    /* Search for matching test case */

    test = NULL;
    for( i=0; i<num_tests; i++ )
    {
        if( tests[i].std     == opt.std &&
            tests[i].bitsize == opt.bitsize )
        {
            test = &tests[i];
            break;
        }
    }

    if( test == NULL )
    {
        mbedtls_printf( "Couldn't find %u-bit prime for RFC %d\n",
                        opt.bitsize,
                        opt.std == DHM_PRIMES_RFC_3526 ? 3526 : 7919 );
        goto usage;
    }

    max_modifiable_bit = test->bitsize - 64;
    nums_digits        = max_modifiable_bit - 64;

    /*
     * Nothing-up-my-sleeve constant:
     * - e for RFC 7919
     * - pi for RFC 3526
     */
    nums_constant = test->std == DHM_PRIMES_RFC_3526 ? pi_hex : e_hex;

    /*
     * Do actual work
     */

    mbedtls_printf( "\n--- Checking %d-bit prime from RFC %u ---\n\n",
                    opt.bitsize,
                    opt.std == DHM_PRIMES_RFC_3526 ? 3526 : 7919 );

    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                       &entropy, (unsigned char*) "test",
                                       4 ) ) != 0 )
    {
        mbedtls_printf( "Failed to seed CTR DRBG\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                        -ret );
        goto cleanup;
    }

    if( opt.check == check_full       ||
        opt.check == check_formula    ||
        opt.check == check_canonicity )
    {
        /*
         * Compute base from which the search for a safe prime starts.
         *
         * Documenting the example of the 2048-bit key in the following
         * for concreteness.
         *
         * In the following, NUMS ([N]othing [U]p [M]y [S]leeve) denotes
         * either pi or e, depending on whether RFC 3526 or RFC 7919 is used.
         */

        /* Set B = 2^2048 */
        MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &B, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &B, test->bitsize ) );

        /* Set B = 2^2048 - 2^1984 - 1 */
        MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &S, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &S, max_modifiable_bit ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &B, &B, &S ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &B, &B, 1 ) );

        /* Read NUMS (pi or e) */
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &NUMS, 16, nums_constant ) );

        /* Compute [2^1918 * NUMS]*/
        nums_len    = mbedtls_mpi_bitlen( &NUMS );
        excess_bits = nums_len - nums_digits;
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &NUMS, excess_bits ) );

        /* Compute 2^64 * [2^1918 * NUMS] */
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &NUMS, 64 ) );

        /* Set B = 2^2048 - 2^1984 - 1 + 2^64 * [2^1918 * NUMS] */
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &B, &B, &NUMS ) );

        /* Save (B-1)/2 in Bp */
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &Bp, &B, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &Bp, 1 ) );

    }

    /* A: Primality testing */
    if( opt.check == check_full || opt.check == check_primality )
    {
        mbedtls_printf( "* Checking for safe primality... " );

        /* Read P and check primality */
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &R, test->ref,
                                                  test->bitsize / 8 ) );

        if( ( ret = mbedtls_mpi_is_prime( &R, mbedtls_ctr_drbg_random,
                                          &ctr_drbg ) ) != 0 )
        {
            mbedtls_printf( "fail!\n" );
            goto cleanup;
        }

        /* Check primality of (P-1)/2 */
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &R, &R, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_r( &R, 1 ) );

        if( ( ret = mbedtls_mpi_is_prime( &R, mbedtls_ctr_drbg_random,
                                          &ctr_drbg ) ) != 0 )
        {
            mbedtls_printf( "fail!\n" );
            goto cleanup;
        }

        mbedtls_printf( "ok\n" );
    }

    /* B: Formula check */
    if( opt.check == check_full || opt.check == check_formula )
    {
        int fail = 0;

        mbedtls_printf( "* Checking formula against hardcoded binary data... " );

        /* Again refering to the 2048-bit example, we still have
         * B = 2^2048 - 2^1984 - 1 + 2^64 * [2^1918 * NUMS] at the moment. */

        /* Add offset * 2^64 to base */
        MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &S, test->offset ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &S, 64 ) );

        /* Set P = 2^2048 - 2^1984 - 1 + 2^64 * ( [2^1918 * NUMS] + offset ) */
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &P, &B, &S ) );

        /* Check that it matches the precomputed value */
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &R, test->ref,
                                                  test->bitsize / 8 ) );

        if( mbedtls_mpi_cmp_mpi( &P, &R ) == 0 )
        {
            mbedtls_printf( "ok\n" );
        }
        else
        {
            mbedtls_printf( "fail!\n" );
            fail = 1;
        }

        if( test->ref_str != NULL )
        {
            mbedtls_printf( "* Checking formula against hardcoded hex data... " );
            MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &P, 16, test->ref_str ) );
            if( mbedtls_mpi_cmp_mpi( &P, &R ) == 0 )
            {
                mbedtls_printf( "ok\n" );
            }
            else
            {
                mbedtls_printf( "fail!\n" );
                fail = 1;
            }
        }

        if( fail == 1 )
            goto cleanup;
    }

    /* C: Canonicity check */
    if( opt.check == check_full || opt.check == check_canonicity )
    {
        mbedtls_printf( "* Checking canonicity of offsets...\n" );

        /* Again refering to the 2048-bit example, we still have
         * B = 2^2048 - 2^1984 - 1 + 2^64 * [2^1918 * NUMS] at the moment. */

        if( opt.stepsize != 1 )
        {
            mbedtls_printf( "  [! Checking only offsets congruent %u modulo %u !]\n",
                            opt.thread, opt.stepsize );
        }

        MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( &B, ( test->bitsize >> 3 ) /
                                             sizeof( mbedtls_mpi_uint ) ) );

        MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( &Bp, ( test->bitsize >> 3 ) /
                                             sizeof( mbedtls_mpi_uint ) ) );

        MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &S, opt.thread ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &S, 64 ) );

        /* Now B = 2^2048 - 2^1984 - 1 + 2^64 * ( [2^1918 * NUMS] + THREAD ) */
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &B,  &B,  &S  ) );

        /* Now we're continuously adding 2^64 * stepsize to B
         * and check when we first find we find a safe prime.
         *
         * During that process, Bp is kept to be (B-1)/2
         * by adding 2^63 in each iteration. */

        MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &Sp, opt.thread ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &Sp, 63 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &Bp, &Bp, &Sp ) );

        MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &S, opt.stepsize ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &S, 64 ) );

        MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &Sp, opt.stepsize ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( &Sp, 63 ) );

        for( i = opt.thread; i <= test->offset; i += opt.stepsize )
        {
            if( i > opt.thread )
            {
                MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &B,  &B,  &S  ) );
                MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &Bp, &Bp, &Sp ) );
            }

            mbedtls_printf( "\r  [%u%%] Checking offset %u/%u...",
                            (unsigned) ( ( i * 100 ) / test->offset ),
                            (unsigned) i, (unsigned) test->offset );
            fflush( stdout );

            ret = mbedtls_mpi_is_prime( &Bp, mbedtls_ctr_drbg_random,
                                        &ctr_drbg );
            if( ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE )
            {
                ret = 0;
                continue;
            }
            else if( ret != 0 )
                goto cleanup;

            ret = mbedtls_mpi_is_prime( &B, mbedtls_ctr_drbg_random,
                                        &ctr_drbg );
            if( ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE )
            {
                ret = 0;
                continue;
            }
            else if( ret != 0 )
                goto cleanup;

            break;
        }

        if( opt.thread == ( test->offset % opt.stepsize ) &&
            i > test->offset )
        {
            mbedtls_printf( "\n  Didn't find any valid offset!\n" );
            goto cleanup;
        }
        else if( opt.thread != ( test->offset % opt.stepsize ) &&
                 i > test->offset )
        {
            mbedtls_printf("\n  Didn't find anything, as expected\n" );
        }
        else
        {
            mbedtls_printf( "\n  Found offset %u: %s\n", i,
                            i == test->offset ? "match" : "fail" );
        }
    }

cleanup:

    mbedtls_mpi_free( &P );
    mbedtls_mpi_free( &R );
    mbedtls_mpi_free( &B );
    mbedtls_mpi_free( &Bp );
    mbedtls_mpi_free( &S );
    mbedtls_mpi_free( &Sp );
    mbedtls_mpi_free( &NUMS );

    mbedtls_entropy_free ( &entropy );
    mbedtls_ctr_drbg_free( &ctr_drbg );

    if( ret != 0 )
    {
        mbedtls_printf( "\nAn error occurred.\n" );
        ret = 1;
    }

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_DHM_C */
