# Free seed mnemonics for steganography and attack-resistance

> "Anyone who considers arithmetical methods of producing  random digits is,  
> of course, in a state of sin." —John Von Neumann

# Abstract

Bitcoin seed mnemonics face attackers ranging from casual thieves to state actors.
We propose soft changes to BIP-39 seed creation to unlock broader mnemonic options
from PBKDF2().
Users of this BIP can generate and store seeds offline with common physical objects
that are plausibly deniable: playing cards, chess boards, and paper napkins to name
a few. As a result seed mnemonics gain greater portability, memorability, entropy,
and steganography as compared to BIP-39 mnemonics.


# Motivation

BIP-39 mnemonic seed phrases have the following shortcomings:

1. BIP-39 seed words, if found by an attacker, are instantly recognizable
as a Bitcoin passphrase to be scrutinized or seized outright.

1. BIP-39 "mnemonics" are not particularly easy to remember.

1. Computing BIP-39's checksum bits necessitates a computer, making offline
seeds impossible.

1. Some hardware vendors support independent sources of entropy such as die rolls
but, unfortunately for the security, convenience, and trust of the users, vary
in how they convert user entropy to the proper binary seed.

    1. Users are required to run their own vendor-specific code to verify that the
    vendor has actually used their provided entropy. Said verification often _still_
    requires blind trust (how does the user know that entropy produced the right
    binary seed?) and is prohibitively technical for many users.

    1. It is cumbersome to manually enter the results of 100 six-sided die rolls,
    the minimum number of rolls to surpass 256 bits of entropy.
    
    1. Die rolls are poor for storing secrets since there are usually fewer dice
    than rolls and since dice are easily mixed up.
    
        > Compare the effort and portability of these 100 rolls
        > to the far easier and more portable shuffled deck of cards.

The above weaknesses cause all Bitcoin wallets to lose,
**due to no fundamental limitation whatsoever**,
the following benefits:

1. Portability in physical media.

1. Portability and memorability in the human brain.

1. Repudiation in high-risk situations where individuals or the Bitcoin protocol
are under attack.

1. The ability to generate, with no electronics, a cryptographically
strong seed that will later work with many hardware wallets.

1. Moore's-law-resistant mnemonics that encode far more than 256 bits of entropy.

    > Although more than 256 bits of entropy exceeds today's ECDSA private keys,
    > it rightfully leaves the door open for stronger keys in the future
    > and further permits today's mnemonics to be repurposed, without change,
    > for tomorrow's larger keys.

**As result, Bitcoin users seeking to evade oppressive governments and other attackers
have fewer defenses than the protocol naturally affords.**

Importantly, the above weaknesses can be remedied with
_little to no change to the BIP-39 seed phrase implementations_ already ubiquitous
in hardware and software wallets.


# Risks, remedies, and alternatives

## Risks

1. Giving users more sources and options for mnemonics increases the
risk that these users provide weak inputs that contain too little entropy or weak
entropy (e.g. common phrases).

    > Implementers must mitigate this risk with an easy-to-implement entropy
    > measure and message to the user.

1. BIP-39 includes checksum bits in the final word, offering some protection
against erroneous entry. The present proposal eliminates both the advantages (integrity)
and disadvantages (cannot be computed by hand) of the BIP-39 checksum bits
in favor of a much broader set of steganographic mnemonics that can be stored,
generated, and carried in situations of urgency and scarcity.

    > BIP-39 checksum validation _shall remain in place_ (unchanged) for BIP-39
    > mnemonics.

    > Advanced users might choose to implement their own checksums or error-correcting
    > codes.


# Specification

**The present spec is fully backwards-compatible with BIP-39 mnemonics**.
We introduce a new input "language" `Free` that admits a superset of BIP-39 mnemonics
Wallets can and should continue to validate BIP-39 mnemonics as in the past.
`Free` should be treated as a new input language, similar to English, French, or
any of the BIP-39 languages.

`Free` should allow at a minimum the ASCII printable characters, minus capital
letters.


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
Applications must _not change_ passphrase entry, validation, normaliztion, or application.

Applications should regard the _mnemonic_ as a raw string to permit the widest
possible array of input characters. (See the following section for details.)

In the interest of backward compatibility we propose that existing BIP-39 implementations
treat `Free` as the tenth input "language" with the following differences from the 9
BIP-39 languages:

1. If they do not already, lower the case of all input letters.
Strangely BIP-39 is silent on the subject of case. 

1. If they do not already, `strip` the `Free` mnemonic of surrounding whitespace
and split it on the regular expression `\s+`.

1. Apply `nfkd()` to the `Free` mnemonic.


```
if language == "Free":
    norm_mnemonic = lower(nfkd(split("\s+", mnemonic)))
    validate(norm_mnemonic)
    PKBDF2(
        password=bin(norm_mnemonic),
        salt=bin(nfkd("mnemonic" || passphrase))),
        hash_name="HMAC-SHA512",
        iterations=2048,
    )
```


The output of PKBDF2 is converted to a master seed as in BIP-39.


## `validate()`

`validate()` must at a minimum estimate the complexity `complexity()` of
the user proposed mnemonic and must refuse the mnemonic if the entropy is less
than a threshold (we recommend a threshold of 0.5).

Implementations must know the cardinality `C` of the mnemonic character set.
Applications must support at a bare minium an input cardinality of **74**
(the number of printable ASCII characters) but higher values for `C` are both
permissible and recommended.  As suggested below, the higher the cardinality of
the input set, the greater the steganographic potential.

    0123456789abcdefghijklmnopqrstuvwxyz!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c


## `complexity()`

The Shannon Entropy `SE` of a string is as follows:

$$ se(X) := - \sum_{i} p(x_i) \log_2 p(x_i) $$

As an optimization for fixed `X` with all unique entries and cardinality `C`:

$$ SE(X) := log_2(C)$$

> Intuitively the above is the (fractional) number of bits needed to represent all
> characters in the `universe`.

The  relative entropy is simply the following:

$$ re(mnemonic\_tokens, universe) := SE(mnemonic) / SE(universe)$$

`universe` is the list of all possible input tokens. `mnemonic_tokens` is a tokenized
list of the inputs. Tokens may vary in length per the universe and application,
though applications can start withe one token per ASCII printable character.

`re()` ranges from 0 to 1 when `mnemonic_tokens` are all unique. An `re()` of 0.5
reflects that the user has provided enough information as providing one instance
of half of all input tokens.

`re()` alone is not a complete measure of password complexity since it does
not take order into account. For instance the string `"abc...xyz"` and its
reverse both have hight relative entropy but are highly predictable.

To correct for this we can use the Hamming Distance, `hd()`, which counts the
number of characters that are not in sorted order:

$$
\text{Hamming Distance} = \sum_{i=1}^{n} (s_i \neq t_i)
$$

Since undesirable order might be forwards of backwards we take the Relative
Absolute Hamming Distance `rahd()`:

```
rahd() := min(hd(norm_mnemonic), hd(norm_mnemonic.reverse())) / len(norm_mnemonic)
```

As with `re()`, `rahd()` ranges from 0 to 1.

```
complexity := (re(norm_mnemonic) + rahd(norm_mnemonic)) / 2
```

If complexity is less than a given threshold (TBD) the wallet should warn the
user.

### TODO: examples of `complexity()` for representative inputs

* [ ] Dice, cards, chess, bad + good text passwords
* [ ] Show how this leads to standard dice verification and fingerprinting
across all hardware vendors (phew)


# Reference implementation 

* https://github.com/akarve/bipsea

## Example

```sh
bipsea validate -f free -m "$(cat input.txt)" | bipsea xprv
```


# Example steganographic mnemonics in `Free`


## Playing cards

A common deck of 52 cards encodes approximately 225 bits of entropy,
more entropy than 21 BIP-39 words. Such decks can be carried on one's person
without raising an eyebrow.

Users might enter cards in deck order as follows:

```
2S 10S kC 10H 5S ...
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
(equivalent to 12 BIP-39 seed words). Random bits can be generated with a coin.


## Any board game

One can imagine steganographic secrets similar to chess for Monopoly, Go, or any
board game.


## Dice, but different

We noted above that if the user were to roll and then store 100 dice that it would
be impractical to retain the original order.
We observe that there are 21 small writing surfaces (the solid dots on each face)
on a six-sided die. If the user were to inscribe a single random digit into each dot
he would obtain approximately 70 bits of ordered entropy. Three such dice would be
easy to retain and order and provide greater entropy than 18 BIP-39 seed words.


## A paper napkin

In addition to a literal napkin sketch (with phone numbers, measurements,
or harmless notes) users without access to coins, dice, game boards or electronics
could generate "poor man's entropy" by dropping a stone onto a napkin divided into 
equal-sized quadrants to generate entropy.

Said "poor man's entropy" is not recommended but nevertheless illustrates
the vast expansion in capability and steganography that obtains from this BIP.
