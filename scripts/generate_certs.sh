#!/bin/sh

if [ -d include/mbedtls ]; then :; else
    echo "$0: must be run from root" >&2
    exit 1
fi

CERTS="library/certs.c"
CERTS_TMP="${CERTS}.tmp"
CERTS_NEW="${CERTS}.new"

# Remove bodies of BEGIN FILE ... END FILE blocks
SED_RM_FILE_BODIES=":o; /BEGIN FILE/!{p;n;bo}; /BEGIN FILE/{p; n; :i; /END FILE/{n; bo}; n; bi}"
sed -n "${SED_RM_FILE_BODIES}" $CERTS > ${CERTS_TMP}
while IFS= read -r line; do
    echo "$line"
    CMD=`echo "$line" | sed -n 's/^\/\* BEGIN FILE \([^ ]*\) \([^ ]*\) \([^ ]*\) \([^ ]*\)*.*$/\1 \2 \3 \4/p'`
    if [ -n "$CMD" ]; then
        enc=$(echo "$CMD" | cut -f1 -d' ' )
        type=$(echo "$CMD" | cut -f2 -d' ' )
        name=$(echo "$CMD" | cut -f3 -d' ' )
        file=$(echo "$CMD" | cut -f4 -d' ' )

        if [ "$type" != "variable" ] && [ "$type" != "macro" ]; then
            exit 1
        fi

        if [ "$enc" != "string" ] && [ "$enc" != "binary" ]; then
            exit 1
        fi

        # Support 'binary' and 'string' encoding
        # Support 'variable' and 'macro' types

        if [ "$enc" = "binary" ]; then
            DATA=`xxd -i "$file" | tail -n +2 | head -n -2 | sed 's/^[ ]*/    /'`
        elif [ "$enc" = "string" ]; then
            DATA=`cat "$file" | sed 's/^/    \"/;s/$/\\r\\n\"/'`
        fi

        if [ "$type" = "variable" ]; then
            if [ "$enc" = "binary" ]; then
                echo "const unsigned char ${name}[] = {"
                xxd -i "$file" | sed 's/^[ ]*/    /' | tail -n +2 | head -n -2
                echo "};"
            elif [ "$enc" = "string" ]; then
                echo "const char ${name}[] ="
                cat "$file" | head -n -1 | sed 's/^/    \"/;s/$/\\r\\n\"/'
                cat "$file" | tail -n 1  | sed 's/^/    \"/;s/$/\\r\\n\";/'
            fi
        elif [ "$type" = "macro" ]; then
            if [ "$enc" = "binary" ]; then
                printf '%-77s\\\n' "#define ${name} {"
                xxd -i "$file" | sed 's/^[ ]*/    /' | tail -n +2 | head -n -2 |
                    xargs -d'\n' printf '%-77s\\\n'
                echo "}"
            elif [ "$enc" = "string" ]; then
                printf '%-75s\\\n' "#define ${name}"
                cat "$file" | head -n -1 | sed 's/^/    \"/; s/$/\\r\\n\"/' | xargs -d'\n' printf '%-75s\\\n'
                cat "$file" | tail -n 1  | sed 's/^/    \"/; s/$/\\r\\n\"/'
            fi
        fi

        echo "/* END FILE */"
    fi
done < ${CERTS_TMP} > ${CERTS}
