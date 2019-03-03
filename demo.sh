#!/bin/bash

DEBUG=0
SALT=$(xxd -p -l 8 < /dev/urandom | tr -d '\n')

usage() {
  cat <<EOF
Usage:
  ${BASH_SOURCE[0]} 256|512 <orig msg> <new msg>
EOF
exit 1
}

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

sha="$1"
msg="$2"
newmsg="$3"
[[ -n $sha && -n $msg && -n $newmsg ]] || usage

ALGO="sha${sha}sum"
if ! /usr/bin/which $ALGO >/dev/null ; then
  if ! /usr/bin/which sha2 >/dev/null ; then
    echo "Can't find sha2 utility. Ensure that either $ALGO or sha2 is installed and in your PATH"
    exit 1
  fi
  ALGO="sha2 -${sha} -q"
fi

explen=$(( ${#SALT} + ${#msg} ))
msgfile=$(mktemp)
newmsgfile=$(mktemp)
echo -n "$msg" > "$msgfile"

sig=$(gen_sig "$msgfile")
minlen=${#msg}
maxlen=$(( explen + 128 ))
echo "Seeding with $sig"
echo "Generated random salt of length ${#SALT}: $SALT"
echo "Trying length of salt+original message: from $minlen to $maxlen. Correct one should be $explen."
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
