Implements the length extension attack. Currently only SHA256 and SHA512 are supported.

# Background

When a message, `msg`, is known and the digest `sha2(salt + msg)` is also known, the digest `sha2(salt + msg + padding + newmsg)` can be calculated without knowing the salt.
`padding` is of the form `\x80\x00...\x00\x??\x??...\x??` where the number of zero bytes is such that `length(salt + msg + padding)` is a multiple of the block size (64 bytes for SHA256 and 128 bytes for SHA512). The final `\x??` bytes are `length(salt + msg)` as a big-endian 64-bit (SHA256) or 128-bit (SHA512) integer.

See also [wikipedia](https://en.wikipedia.org/wiki/Length_extension_attack).

# Installation

```
make && make install
```

Default install prefix is `/usr/local`, change with `make PREFIX=<prefix>`.

At the moment the algorithm is chosen at compile time and defaults to SHA512. Change to SHA256 with `CFLAGS=-DUSE_SHA256 make`.

There is a `demo.sh` that will find the correct padding that gives a valid signature for `salt + msg + newmsg`, given `msg` and `newmsg` (`salt` is randomly generated).

# Usage

The attack proceeds as follows. The SHA algorithm is seeded with the known message digest and for each possible `length(salt + msg)`, the `newmsg` is appended and the new digest is calculated. The digest changes only then the `length(salt + msg + padding) mod (block size)` wraps around.

For convenience the program accepts a minimum and a maximum length and for each length the length and the required padding are printed, delimited by tab. The digest is only recalculated and printed when it changes.
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
