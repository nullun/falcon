# Portable known-answer tests for deterministic Falcon

The KAT arrays compiled into `tests/test_deterministic512.c` and
`tests/test_deterministic1024.c` derive each private key by running this
implementation's own key generator over a seeded PRNG. The number and order of
PRNG draws made during key generation is implementation-specific, so no other
implementation can reproduce those keys, and therefore none of those vectors
can be used to check a port in another language.

The files in this directory re-export the same vectors in a self-contained,
language-neutral form. Every record carries the private key, the public key and
the message as literal bytes, so reproducing a record needs only a signer and a
verifier — never a matching key generator.

| File | Parameter set | Records | Checkpoints |
| --- | --- | --- | --- |
| `falcon_det512.rsp` | FALCON-DET512 (`n = 512`) | 32 | yes |
| `falcon_det1024.rsp` | FALCON-DET1024 (`n = 1024`) | 32 | yes |

Both files are produced by `tests/kat_tool`, which cross-checks every signature
it emits against the committed C KAT headers before writing it. A portable file
can therefore never disagree with the vectors the existing test programs
enforce.

## Regenerating and checking

    make kat         # regenerate the committed core files
    make check-kat   # re-derive every record and compare against the files
    make kat-full    # write the exhaustive 512-record files to kat/full/

`check-kat` re-signs each stored message under the stored private key and
verifies both signature forms against the stored public key. That is exactly
the path a port in another language takes, so a failure there means the file is
wrong rather than the port. The exhaustive files are not committed: they are
around 4 MB and 7 MB respectively, and add message-length coverage rather than
new behaviour.

## Format

A line-oriented text format, chosen so that a parser is a few lines in any
language. Blank lines are insignificant and lines whose first non-blank
character is `#` are comments. Every other line is `key = value`. Byte strings
are lowercase hex with no separators; an empty value is a zero-length string.

A header block appears once, before any record:

| Field | Meaning |
| --- | --- |
| `alg` | `FALCON-DET512` or `FALCON-DET1024` |
| `format_version` | currently `1`; bump on any incompatible change |
| `logn`, `n` | degree, as `log2(n)` and as `n` |
| `privkey_len`, `pubkey_len`, `sig_ct_len` | fixed lengths for this parameter set |
| `sig_compressed_maxlen` | upper bound; compressed signatures vary in length |
| `records` | number of records that follow |
| `checkpoints` | `yes` if records carry the optional `c`, `s1`, `s2` fields |

Each record then begins with `count` and carries:

| Field | Meaning |
| --- | --- |
| `count` | record index, also the message length for the standard sets |
| `salt_version` | salt version byte the signer used |
| `msg_len` | message length in bytes; must agree with `msg` |
| `privkey` | Falcon private key, round-3 encoding |
| `pubkey` | Falcon public key, round-3 encoding |
| `msg` | message to be signed |
| `sig_compressed` | deterministic signature, unsalted compressed format |
| `sig_ct` | the same signature transcoded to unsalted CT format |

A consumer must accept records in which the optional checkpoint fields below
are absent, and should reject a record carrying a field it does not recognise.

## Checkpoint fields

The checkpoint fields are intermediate values of verification. They exist so
that a port under development fails at the stage that is actually broken
instead of reporting only "signature does not match". Each is a vector of `n`
16-bit words, written little-endian, signed values in two's complement.

| Field | Stage it isolates |
| --- | --- |
| `c` | `SHAKE256` over the versioned salt and message, and hash-to-point rejection sampling |
| `s2` | signature decoding — `trim_i16_decode` over the CT form |
| `s1` | arithmetic mod `q` — `s1 = c - s2*h`, via the NTT |

A port should check them in that order: `c` depends only on hashing, `s2` only
on the codec, and `s1` on both plus the NTT. `c` is computed from the message
and `salt_version`; `s2` is decoded from `sig_ct`; `s1` is derived from `c`,
`s2` and the public key.

Note that `s1` is also the point at which the signature's shortness is checked.
A port that recovers `s1` correctly and computes `‖(s1, s2)‖² ≤ ⌊β²⌋` has
implemented verification; reproducing `sig_compressed` from `privkey` and `msg`
additionally requires a bit-exact deterministic signer.
