Implements the length extension attack. Currently only SHA256 and SHA512 are supported.

# Background

When the digest of a message, `msg`, is known, the digest `sha2(msg + padding + newmsg)` can be calculated without knowing the original message.
`padding` is of the form `\x80\x00...\x00\x??\x??...\x??` where the number of zero bytes is such that `length(msg + padding)` is a multiple of the block size (64 bytes for SHA256 and 128 bytes for SHA512). The final `\x??` bytes are `length(msg)` as a big-endian 64-bit (SHA256) or 128-bit (SHA512) integer.

See also [wikipedia](https://en.wikipedia.org/wiki/Length_extension_attack).

In practice one often knows a message, `msg`, and the digest `sha2(salt + msg)` without knowing the salt. Then the digest `sha2(salt + msg + padding + newmsg)` can be calculated without knowing the salt. This happens when a server application generates an authentication token of the form `<user information>.<signature = digest(salt + <user information>)`. The user can then append arbitrary content to `<user information>` and generate a valid signature for the new message, potentially authenticating with as a different user.

# Installation

Tested only on Linux. You need the openssl header files (probably provided by libssl-dev).

```
make && make install
```

Default install prefix is `/usr/local`, change with `make PREFIX=<prefix>`.

At the moment the algorithm is chosen at compile time and defaults to SHA512. Change to SHA256 with `CFLAGS=-DUSE_SHA256 make -B`.

There is a `demo.sh` that will find the correct padding that gives a valid signature for `salt + msg + newmsg`, given `msg` and `newmsg` (`salt` is randomly generated).

# Usage

The attack proceeds as follows. The SHA algorithm is seeded with the known message digest and for each possible `length(salt + msg)`, the `newmsg` is appended and the new digest is calculated. The digest changes only when the `length(salt + msg + padding) mod (block size)` wraps around.

The program accepts a minimum and a maximum `l = length(salt+msg)` . For each `l`, `l` and the required padding is printed, delimited by tab. The digest is only recalculated and printed when it changes.

The padding, `p`, that corresponds to `l = length(salt+msg)` will be the correct one for `d = sha256(salt+msg+p+newmsg)`, where `d` is the most recently printed digest.

```
Options:
  -m <str>     Message to append.
  -d <hex str> Digest to begin with.
  -l <int>     Minimum length of salt + original message.
               Default is 1.
  -L <int>     Maximum length of salt + original message.
               Default is 1024.
  -s <int>     Step to increment length.
               Default is 1.
```

# Example:

A user knows the digest `d = 3ac7e4747eced02faeed89e46a19b4ad7e6cc7855135a0b7f0d8e296f611bbd8` for `sha256(salt+msg)`, where message is "foo". He suspects the salt is between 1 and 5 characters, and wants to append "bar" to the message.
```
$ ./sha_lext_attack -d 3ac7e4747eced02faeed89e46a19b4ad7e6cc7855135a0b7f0d8e296f611bbd8 -m bar -l 4 -L 8
digest:	7315b0ce26699aaadaaf22f98693a7fc6a52c322a403d2836cb4c8eab4ee9ca4
    4	\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20
    5	\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x28
    6	\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30
    7	\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x38
    8	\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40
```

The user needs to validate the signature for each possible padding, by sending it to the black box which knows the secret salt, e.g. the authentication server. The message they send will be "foo`<padding>`bar" and signature will be 7315b0ce26699aaadaaf22f98693a7fc6a52c322a403d2836cb4c8eab4ee9ca4.

In this case the salt was 123, one can verify that the correct padding is indeed for `l = 6`:
```
$echo -n '123foo' | sha256sum 
3ac7e4747eced02faeed89e46a19b4ad7e6cc7855135a0b7f0d8e296f611bbd8  -

$echo -n -e '123foo\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30bar' | sha256sum
7315b0ce26699aaadaaf22f98693a7fc6a52c322a403d2836cb4c8eab4ee9ca4  -
```

