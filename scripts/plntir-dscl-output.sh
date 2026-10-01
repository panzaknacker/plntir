#!/bin/bash

# match exactly one value from the human-readable output produced by macOS dscl.
# depending on the local directory record, dscl prints either:
# attribute: value
# or:
# attribute:
# value
plntir_dscl_output_has_value() {
    if [[ $# -ne 1 || -z $1 ]]; then
        return 64
    fi

    local expected=$1
    /usr/bin/awk -v expected="${expected}" '
        NR == 1 {
            sub(/^[^:]*:[[:space:]]*/, "")
        }
        NR > 1 {
            sub(/^[[:space:]]*/, "")
        }
        length($0) > 0 {
            values++
            if ($0 == expected) {
                matches++
            }
        }
        END {
            exit !(values == 1 && matches == 1)
        }
    '
}

plntir_dscl_attribute_has_value() {
    if [[ $# -ne 3 ]]; then
        return 64
    fi

    local record=$1
    local attribute=$2
    local expected=$3
    local output
    if ! output=$(/usr/bin/dscl . -read "${record}" "${attribute}" 2>/dev/null); then
        return 1
    fi
    /usr/bin/printf '%s\n' "${output}" | plntir_dscl_output_has_value "${expected}"
}
