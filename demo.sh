#!/bin/bash

DEBUG=0
SALT=$(xxd -p -l 120 < /dev/urandom | tr -d '\n')
ALGO='sha512sum'

gen_sig() {
    local msgfile="$1" sig
    sig=$( (echo -n "$SALT" ; cat "$msgfile" ) | $ALGO | cut -d\  -f1 | tr -d '\n' )
    echo "$sig"
}

ver_sig() {
    local msgfile="$1" sig="$2" truesig
    truesig=$(gen_sig "$msgfile")
    (( DEBUG )) && echo -e "  $sig\n  vs\n  $truesig" >&2
    if [[ $sig != $truesig ]] ; then
        echo "Invalid signature"
    else
        echo "Good signature"
    fi
}

if [[ $# -ne 2 ]] ; then
    echo "Usage: ${BASH_SOURCE[0]} <msg> <newmsg>"
    exit 0
fi

msg="$1"
newmsg="$2"
[[ -n $msg && -n $newmsg ]] || exit 1

explen=$(( ${#SALT} + ${#msg} ))
msgfile=$(mktemp)
newmsgfile=$(mktemp)
echo -n "$msg" > "$msgfile"

sig=$(gen_sig "$msgfile")
minlen=${#msg}
maxlen=$(( explen + 128 ))
echo "Seeding with $sig"
echo "Trying lengths $minlen to $maxlen"
while read -r one two ; do
    if [[ "$one" == digest* ]] ; then
        newsig="$two"
        (( DEBUG )) && echo "NEW: $newsig" >&2
    else
        len="$one"
        padding="$two"
        (echo -n "${msg}" ; echo -e -n "${padding}" ; echo -n "${newmsg}") > "$newmsgfile"
        (( DEBUG )) && echo "LEN: $len" >&2
        res=$(ver_sig "$newmsgfile" "$newsig")
        if [[ $res == Good* ]] ; then
            echo "Good signature for length(salt+msg) = $len:"
            echo "$newsig"
            if [[ $len -eq $explen ]] ; then
                exit 0
            else
                echo "Expected good sig at length $explen"
                exit 1
            fi
        fi
    fi
done < <(./sha_lext_attack -m "$newmsg" -d "$sig" -l $minlen -L $maxlen -s 1)

rm "$msgfile"
rm "$newmsgfile"
echo "Couldn't find a good signature"
exit 1
