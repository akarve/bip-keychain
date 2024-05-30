# Steganographic seed mnemonics for usability and attack-resistance

> "Anyone who considers arithmetical methods of producing random digits is,
> of course, in a state of sin." —John Von Neumann

# Abstract

Bitcoin wallets face scrutiny from attackers ranging from casual thieves to state
actors. With little to no implementation changes, we unlock greater mnemonic
possibilities from PBKDF2(), widely used by all BIP-39-compatible wallets.
Users of this BIP can generate and store seeds with easy-to-repudiate
physical objects including playing cards, chess boards, and paper napkins.
As a result seed mnemonics enjoy greater portability, entropy, and steganography.


# Motivation

BIP-39 mnemonic seed phrases have the following shortcomings:

1. BIP-39 seed words, if found by an attacker, are instantly recognizable
as a Bitcoin passphrase to be scrutinized or seized outright.

1. BIP-39 "mnemonics" are not particularly easy to remember.

1. Computing BIP-39's checksum bits necessitates a computer,
making pure offline seeds impossible.

1. Some hardware vendors support independent sources of entropy such as die rolls
but, unfortunately for the security, convenience, and trust of the users, vary
in how they convert user entropy to the proper binary seed.

    1. Users are required to run their own vendor-specific code to verify that the
    vendor has actually used their provided entropy. Said verification often _still_
    requires blind trust (how does the user know that entropy produced the right
    binary seed?) and is prohibitively technical for many users.

    1. It is cumbersome to manually enter the results of 100 six-sided die rolls,
    the minimum number of rolls to surpass 256 bits of entropy.
    
    1. Dice rolls are poor for storing secrets since there are usually fewer dice
    than rolls and since dice are easily mixed up.
    
        > Compare the effort and portability of these 100 rolls
        > to the far easier and more portable shuffled deck of cards.

The above weaknesses cause all Bitcoin wallets to lose,
_due to no fundamental implementtion limit whatsoever_,
the following benefits:

1. Portability in physical media.

1. Portability and memorability in the human brain.

1. Repudiation in high-risk situations where individuals or the Bitcoin protocol
are under attack.

1. The ability to generate, with no electronics, a cryptographically
strong seed that will later work with many hardware wallets.

1. Moore's-law-resistant mnemonics with far more than 256 bits of entropy.

    > Although 257 bits begins to exceed today's ECDSA private keys,
    > it rightfully leaves the door open for stronger keys in the future
    > and further permits repurposing of today's mnemonics for tomorrow's larger
    > keys.


**As result, Bitcoin users seeking to evade oppressive governments and other attackers
have fewer defenses than the protocol naturally affords.**

Importantly, the above weaknesses can be remedied with
_little to no change to the BIP-39 seed phrase implementations_ already ubiquitous
in hardware and software wallets.


# Risks, remedies, and alternatives

We note that **the present spec is a _soft_ modification of BIP-39**. We propose
that wallets admit a proper superset of BIP-39 mnemonics.
Any and all existing BIP-39 mnemonics and passphrases are fully compatible with
this BIP.



## Risks

1. Giving users more sources and options for mnemonics increases the
risk that these users provide weak inputs that contain too little entropy or weak
entropy (e.g. common phrases).

    > Implementers will mitigate this risk with an easy-to-implement entropy
    > measure and warning to the user.

1. BIP-39 includes checksum bits in the final word, offering some protection
against erroneous entry. The present proposal surrenders both the advantages (integrity)
and disadvantages (cannot be computed by hand) of the BIP-39 checksum bits
in favor of a much broader set of steganographic mnemonics that can be stored,
generated, and carried in situations of urgency and scarcity.

    > Advanced users can choose to implement their own checksums or error-correcting
    > codes.


## Alternatives

Alternative to the proposed soft changes to BIP-39, it is admittedly possible to
generate a master key with either the BIP-32 algorithm on `PBKDF2(mnemonic)`
and then use BIP-85's application `32'` to derive new seed words. But this would
not benefit the Bitcoin community as quickly or as broadly as standing on the
shoulders of the far more widely supported BIP-39.


# Specification

BIP-39 derives binary seeds by applying `PBKDF2()` to a mnemonic and passhprase
as follows:


```
PKBDF2(
    password=bin(nfkd(mnemonic)),
    salt=bin(nfkd("mnemonic" || passphrase)),
    hash_name="HMAC-SHA512",
    iterations=2048,
)
```

`nfkd()` converts the input string to Unicode normalization form KD.

Fortunately `PBKDF2()` does not limit the domain either the `password` or `salt`
argument. Existing implementations are therefore easy to update.
We propose _no change_ to passphrase entry, validation, or application.

Applications should regard the _mnemonic_ as a raw string to permit the widest
possible array of input characters. (See the following section for details.)

In the interest of backward compatibility we propose that existing BIP-39 implementations
make only the following changes:

1. If they do already, relax any input validation that requires the mnemonic to
come from a BIP-39 word list.

1. If they do not already, lower the case of `nfkd(mnemonic)` to reduce the
impact of entry errors.

    > Although this reduces input entropy, we believe it is a tradeoff
    > worth making to improve the likelihood of user access to their funds.

1. If they do not already, introduce a `validate()` routine that measures, and
possibly rejects, the simplified entropy of the input mnemonic.

With these small changes the world of steganograpic seeds and all of the benefits
outlined above accrue to Bitcoin users.

The soft alteration and proposed application of `PBKDF2()` follows:

```
norm_mnemonic := lower(nfkd(mnemonic))

if validate(norm_mnemonic):
    PKBDF2(
        password=bin(norm_mnemonic),
        salt=bin(nfkd("mnemonic" || passphrase))),
        hash_name="HMAC-SHA512",
        iterations=2048,
    )
```

> Current implementations likely already perform a validation pass to check for proper,
> localized BIP-39 seed words.


## `validate()`

`validate()` must at a minimum estimate the simplified Shannon entropy `E()` of
the user proposed mnemonic and must refuse the mnemonic if the entropy is less
than 128 bits (equivalent to 12 BIP-39 seed words).

Implementations must know the cardinality `C` of the mnemonic character set.
Applications must support at a bare minium an input cardinality of **44**
(26 letters, 10 digits, punctuation including `-, !, ?, {, }, ', +, =`)
but higher values for `C` are both permissible and recommended.
As suggested below, the higher the cardinality of the input set, the greater the
steganographic potential.

More nuanced and even off-the-shelf password complexity measures might also be used
for stricter validation provided that they do not invalidate any BIP-39 inputs.
Said complexity measures must be submitted to this spec for consistent results
across wallet vendors.


### Simplfied Shannon entropy, `E()`

$$ E(mnemonic) := \log_2(C^{len(mnemonic)}) $$


# Examples


## Playing cards

A common deck of 52 cards encodes approximately 225 bits of entropy,
more entropy than 21 BIP-39 words. Such decks can be carried on one's person
without raising an eyebrow.

Users might enter cards in deck order as follows:

```
2s-10s-Kc-10h-5s-...
```

## Chess, three different ways


### Fictional move order

A chess board contains 64 totally ordered squares each of which can be addressed
in algebraic notation of the form `{a-h}{1-8}`. A move specifies one of five piece
types (`R, N, B, Q, K`) followed by a square.
`Nf1` is an example of a single knight move.
A series of 42 chess moves written on an easy-to-repudiate, easy-to-obfuscate,
piece of paper encodes at least as much entropy as 24 BIP-39 seed words.

$$ \log_2(69^{42}) \approx 256 $$

Ensuring that such moves comprise a valid chess game (and thus greater steganography)
is a hard problem and is neither required nor recommended in the context of this BIP.
It is not recommended since it constrains the potential entropy in unclear and
hard-to-reckon ways.


### PGN files

Nevertheless, high steganography in a chess game can be achieved with file formats
that support comments, such as the common PGN format. Observe the following snippet
from a PGN file and note the opportunities for arbitrary comments.


```
[Event "Third Rosenwald Trophy"]
[Site "New York, NY USA"]
[Date "1956.10.17"]
[EventDate "1956.10.07"]
[Round "8"]
[Result "0-1"]
[White "Donald Byrne"]
[Black "Robert James Fischer"]
[ECO "D92"]
[WhiteElo "?"]
[BlackElo "?"]
[PlyCount "82"]

1. Nf3 Nf6 2. c4 g6 3. Nc3 Bg7 4. d4 O-O 5. Bf4 d5 6. Qb3 dxc4
7. Qxc4 c6 8. e4 Nbd7 9. Rd1 Nb6 10. Qc5 Bg4 11. Bg5 {11. Be2
followed by 12. O-O would have been more prudent. The bishop
move played allows a sudden crescendo of tactical points to be
uncovered by Fischer. -- Wade} Na4 {!}
```


### Marked game boards

Alternatively a user might choose to subtly mark the 64 squares of two chess boards
to represent a 1 or 0 in each of 128 unique positions, storing 128 bits of entropy
(equivalent to 12 BIP-39 seed words).


## Any board game

One can imagine steganographic secrets similar to chess for Monopoly, Go, or any
board game.


## Dice but different

We noted above that if the user were to roll and then store 100 dice that it would
be impractical to retain the original order.
We observe that there are 21 small writing surfaces (the solid dots on each face)
on a six-sided die. If the user were to inscribe a single random digit into each dot
he would obtain approximately 70 bits of ordered entropy. Three such dice would be
easy to retain and order and provide greater entropy than 18 BIP-39 seed words.


## A paper napkin

In addition to a literal napkin sketch (with putative phone numbers, measurements,
or harmless notes) users without access to coins, dice, game boards or electronics
could generate "poor man's entropy" by dropping a stone onto a napkin divided into 
equal-sized quadrants to generate entropy.

Said "poor man's entropy" is not recommended but is provided as an illustration of
the vast expansion in capability and steganography that obtains from this BIP.
