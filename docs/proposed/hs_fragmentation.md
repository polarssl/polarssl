# Summary

At the momement, TLS handshake fragmentation is not supported. In particular
this limits the max certificate length that mbedTLS client can receive.

## Goals

1. Full backwards compatibility with the mbedTLS 2.7 version, unless the user
   explicitly enables fragmentation support in `config.h`.
2. Minimizing the conceptual changes to the mbedTLS 2.7 codebase.
3. Robustness and simplicity.

## Non-goals

1. Minimal memory footprint when the fragmentation is enabled.

# Detailed description of the problem

TLS handshake messages can exceed the maximal TLS record size. Examples include large certificates.

If the handshake message is fragmented, the handshake header is included in the
TLS record that carries the first fragment. Payload of the TLS records that
carry subsequent fragments starts with a body at some offset.

The simple scenario assumes that the fragmented handshake message starts and
ends at the record boundary:

```
+---------------------------+    +---------------------+
|TLS                        |    |TLS                  |
|hdr | payload              |    |hdr | payload        |
+----+----------------------+    +----+----------------+
     | +------+------------+|         | +------------+ |
     | |HS Hdr|Body Frag 0 ||  ...    | |Body Frag #n| |
     | +------+------------+|         | +------------+ |
     +----------------------+         +----------------+
```

A more realistic scenario includes the possibility that the first fragment is
preceded by data that belongs to a different handshake message , or that the
last fragment is followed by another message

A more realistic scenario drops the assumption. The TLS record that carries the
first fragment can start with "leading data", which belongs to the preceding
handshake message.

Similarly, the TLS record that carries the last fragment can include "trailing
data", which belongs to the following handshake message.

Finally, the fragmented message can be bracketed between the "leading" and
"trailing" data:

```
+--------------------------------------+    +-------------------------------------+
|TLS                                   |    |TLS                                  |
|hdr | payload                         |    |hdr | payload                        |
+----+---------------------------------+    +----+--------------------------------+
     |  +--------+------+------------+ |         | +------------+------+--------+ |
     |  |.. data |HS Hdr|Body Frag 0 | |   ...   | |Body Frag #n|HS Hdr|data ...| |
     |  +--------+------+------------+ |         | +------------+------+--------+ |
     +---------------------------------+         +--------------------------------+
```

## Proposed change

The input/output model of MbedTLS 2.7 assumes that the entire message will fit
in the `ssl->in_buf`. This proposal keeps this assumption, so that the
conceptual changes will be kept at minimum.

Supporting the fragmented handshake messages comprises:

1. Memory management.
2. Accumulating handshake fragments.

The behavior of the defragmentation is controlled by:
- `MBEDTLS_SSL_HS_DEFRAG` - enable defragmentation.
- `MBEDTLS_SSL_HS_DEFRAG_MAX_SIZE` - upper limit for the handshake message.

### Memory management

There are several alternatives to the memory management, with different
trade-offs between the RAM footprint and the simplicity of the implementation.

The suggested approach keeps the implementation simple, and minimizes the
changes to the codebase. As a trade-off, it uses more memory than the absolute
minimum.

The `in_buf` buffer size is increased by `HS_DEFRAG_MAX_SIZE + IN_CONTENT_LEN`
bytes, and is logically divided into three "zones":

1. the "TLS record zone", which is used exactly like `ssl->in_buf` is used
   today, for both accumulating data from `ssl->f_recv` and for
   decryption/decompression.

2. the "defrag zone", which is used to reassemble message fragments.

3. the "spill zone", which is reserved for the "trailing data" past the last
   fragment of a handshake message.

```
  in_msg   ----+                   |                      |                  |
               |<--IN_CONTENT_LEN->|<-HS_DEFRAG_MAX_SIZE->|<-IN_CONTENT_LEN->|
  in_hdr   -+  |                   |                      |                  |
            v  v                   |                      |                  |
  +--------------------------------+----------------------+------------------+
  |in_buf        "tls record zone" |   "defrag zone"      |  "spill zone"    |
  |                                |                      |                  |
  +--------------------------------+----------------------+------------------+
                                   ^                      ^
    defrag_hs_start ---------------+                      |
                                                          |
     defrag_hs_end  --------------------------------------+

```

With this approach, the location of the `in_msg`, `in_hdr` and `in_iv` does not
change during the operation. Because of this, functions such as
`ssl_parse_server_hello`, which assume that `ssl->in_msg` does not move, will
not have to be modified:

```
static int ssl_parse_server_hello( mbedtls_ssl_context *ssl )
{
...
    buf = ssl->in_msg;

    if( ( ret = mbedtls_ssl_read_record( ssl, 1 ) ) != 0 )
    {
        /* No alert on a read error. */
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        return( ret );
    }
...
}
```

### Accumulating handshake fragments

Proposed changes include:

1. Changing `mbedtls_ssl_prepare_handshake_record()`, so that whenever
   the condition `ssl->in_msglen < ssl->in_hslen` is true, the `WANT_READ` is
   returned instead of `FEATURE_UNAVAILABLE` error.

2. Changing the `ssl_consume_current_message()`, so that whenever it finds that
   `ssl->in_msglen < ssl->in_hslen`, it does not reset `ssl->in_hslen` if
   defragmentation is supporrted.


#### Changes to `mbedtls_ssl_prepare_handshake_record()`

When `mbedtls_ssl_prepare_handshake_record()` detects that only a fragment of the
handshake message is available in the record, it copies the fragment to the
defragmentation area:

```
  in_msg   ----------+                     |                                    |
                     |                     |                                    |
  in_hdr   -----+    |<---IN_CONTENT_LEN-->|<------HS_DEFRAG_MAX_SIZE---------->|
                |    |                     |                                    |
                v    v                     |                                    |
  +----------------------------------------+------------------------------------+
  |in_buf             +---------------+    |    +---------------+               |
  |                   |frag #k        |    |    |fragment #k-1  |               |
  |                   |               |    |    |               |               |
  |                   +---------------+    |    +---------------+               |
  +---------------------------+------------+----------------------^-------------+
                              |                                   |             |
                              +---copy past the prev segment------+
```

If the copied fragment was not the last (`(defrag_hs_end - defrag_hs_start) < ssl->in_hslen`),
`mbedtls_ssl_prepare_handshake_record()` returns `WANT_READ` error (instead of the
`FEATURE_UNAVAILABLE`).  The `WANT_READ` error code is propagated through the handshake parsing
functions up to the application code, so that it knows that more input is
needed by the state machine.

Otherwise, if the copied fragment was the last (`ssl->in_hslen <=
(defrag_hs_end - defrag_hs_start)`), `mbedtls_ssl_prepare_handshake_record()`
moves the defragmented data `ssl->in_hdr`, so that the parsing functions will
find the handshake data in the expected locations.

## Alternative approaches

I have considered using a separate buffer to keep the reassembled buffer. This
approach has the potential of using only the required space, instead the large
arena suggested earlier.

Doing so requires a more invasive change to the code base, since the code
generally assumes that once the `ssl->in_buf` has been allocated, the
`ssl-in_hdr` et al pointers do not change.

Since minimizing the changes to the 2.7.x branch is a high priority, I have
decided against the more optimal approach.

Additional consideration is that this change is intended to be used on desktop
platforms, which have ample memory.

In contrast to the 2.7.x branch, the `development` branch would allow more
granular memory management.

# Detailed description of the change

## Overview of the handshake read path

The read flow is triggered by the application invoking `mbedtls_ssl_handshake()`,
either directly or via `mbedtls_ssl_read()`. When the handshake flow requries
data, it invokes `ssl_read_record()`.

If there is no pending data in the `ssl->in_buf`, `ssl_read_record()` attempts
to read the next TLS record with `ssl_get_next_record()`, which performs the
following steps:

1. It reads the header of the handshake message via `mbedtls_ssl_fetch_input()`
2. It parses and validates the header via `ssl_parse_record_header()`.
3. If the record is invalid, it stops processing and propagates the error up the stack.
4. Otherwise, it reads the message body via `mbedtls_ssl_fetch_input()`
   and proceeds to the next steps.
