 ```
  BIP: ?
  Layer: Applications
  Title: General secrets keychain with semantic derivation paths
  Author: Aneesh Karve <dowsing.seaport0d@icloud.com>
  Discussions-To: <dowsing.seaport0d@icloud.com>
  Comments-Summary: No comments yet.
  Comments-URI: https://github.com/akarve/bip-keychain
  Status: Draft
  Type: Informational
  Created: 2024-05-27
  License: BSD-2-Clause
  Post-History: n/a
  Requires: 32, 44, 85
  Replaces: n/a
```

# BIP-Keychain: General secrets keychain with semantic derivation paths

# Abstract

We further generalize the hierarchical deterministic wallet chain from BIP-32
with a new application code for BIP-85 and a deterministic path derivation algorithm
that allows applications to create a large key-value map of secrets where the key
for each secret is a meaningful semantic path, as opposed to arbitrary integers.
This secure key-value map can replace modern password managers and offers a harder
and more trustless security profile.


# Definitions

* "key" may mean "key" in the sense of key-value store, whereas "master key"
implies an extended private key (XPRV)
* a path "segment" is one token in a `/`-separated derivation path (`seg_1/seg_2`)
* "application", depending on context, sometimes means "application code" from
BIP-85 but usually means an "application" that implements the current spec


# Motivation

BIP-85 specifies how to derive passwords, private keys, and entropy from paths
of the following form:

```
m/83696968'/{app_no}'/{index}'
```

Nevertheless BIP-85 has the following ambiguities and shortcomings:

1. Application codes are arbitrary integers.

1. Path construction is arbitrary in that there is no well-defined procedure to
extend the path for applications that require more than two parameters.
The implied convention is for paths to end with `{some_integer_n}'{index}'`
but there is no guidance on the order of parameters for applications that need more
than two parameters.

1. Return types for applications vary in interpretation and are not specific
enough to be actionable. For example sometimes `n` represents the
number of bytes, sometimes the number of characters, sometimes the number of
BIP-39 words, etc.

Moreover, modern password managers protect hot child secrets with a single root
master hot secret such that if the master secret is compromised all children are
also compromised.

BIP-Keychain proposes a new paradigm where numerous hot or cold secrets are derived
from hot but non-secret-compromising _derivation path keys_ that are in turn stored
under a hot master secret such that if this hot master is compromised only the
_derivation path keys_ but not the actual child secrets (_derivation path values_)
are compromised. In spirit this is similar to how user-authentication databases
store a non-sensitive hash image of the password and not the password itself.

Said hot master secret can itself be the child derivative of a
cold master key. The master key for deriving the secret values need not be stored
online nor with the derivation path keys and may be provided just-in-time by the
application or server.

Moreover, _generalized derivation paths_ may be interpreted not simply as an
input to key derivation but also as information about the real world. 


# Assumptions and risks

1. Long, many-segment derivation paths of potentially thousands of segments should
work in terms of memory, application support, and derivation time.

1. Although BIP-85 recommends fully hardened derivation it is useful to relax
this constraint in order to give application authors more freedom to, for instance,
furnish non-hardened children (and parents) for general PKI use cases such
as recipient-verifiable signatures.


# Specification

BIP-Keychain builds upon BIP-85 with the new application code `67797668'`.
We define the _fully qualified semantic path image_ as a derivation path
of the following form:

```
m/83696968'/67797668'/{SEMANTIC_PATH_IMAGE}
```

The fully qualified semantic path image consists of one or more semantic segment
images. Each segment image is a standard child index that we can think of as
an unsigned integer in the interval [0, 2^31 - 1], followed by an optional `'`
to indicate hardened derivation per BIP-44.

The fully qualified semantic path image is derived from a
_fully qualified semantic path pre-image_ that consists of one or more semantic
segments concluded by a standard child index.

```
FULL_SEMANTIC_IMAGE := {i(s_0)}/{i(s_1)}/.../{i(s_n)}/{index}
```

`i()` is an image function that converts a semantic segment pre-image into
an integer child image index. Each `s_n` is a semantic segment. `i()` and `s_n`
are defined in the following section.

The construction, derivation, and custody of semantic images and pre-images are
the heart of the present spec.


## Semantic pre-images

The semantic path pre-image fully and repeatably determines the semantic path image
and therefore the BIP-32 derivation path.  Each segment `s_i` in a semantic path
pre-image is a single JSON object that instantiates a single
[schema.org](https://schema.org) entity in JSON-LD format.

```
{s_0}/{s_1}/.../{s_n}/{index}
```
 `index` must be a standard BIP-32 child index that is not altered by imaging.

By convention but not requirement we suggest the following:

1. The first semantic path segment is an application managed _namespace_ that may
represent a role, team, company, or similar unit of organization.

1. The penultimate semantic path segment is a `CreateAction` instance that specifies
the format of entropy derivation desired by the user or application.

1. Semantic paths for most applications should contain 4 or fewer segments where
each segment is no more than 1kB in size.

> Applications may choose to implement longer paths and larger segments.
> In any case, the impact of semantic path size on derivation path size is
> negligible since each semantic path segment maps to a 32-bit child index of
> constant size in the semantic image.


## Computing semantic images from pre-images with `i()`

Suppose that we wish to convert a semantic segment `s_n` to an image segment `i(s_n)`.

```
i := int(hmac(jcs(S_N)), "big") >> (512 - 31)
```

`int(x, "big") >> (512 - 31)` denotes the most significant 31 bits of the `hmac()`
value. The application may set the leading bit depending on whether or not hardened
derivation is desired. The result is a 32-bit child index.

Compute `hmac()` as follows:

```
hmac := hmac_sha_512(
    key=bip85_ent(master, m/83696968'/67797668'/{parent_semantic_image}),
    msg=(jcs(s_n)) || optional_nonce
)
```

`bip85_ent` returns the 64 bytes of entropy from the BIP-85 derivation of the _parent_ path.
Using this entropy as the hmac key ensures that, even though repeated and identical
JSON-LD entities are likely for a single user or team of users, collisions remain
exceedingly rare.

We use SHA-512 as the digest for `hmac`. `jcs` is  the JSON Canonicalization Scheme
(JCS) from [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) to ensure
message digest consistency.

We define big `I()` as follows:

```
I(full_semantic_pre_image) := {i(s_0)}/{i(s_1)}/.../{i(s_n)}/{index}
```


## Semantic segment examples

### Web passwords

A common semantic path pre-image might be a `WebSite` followed by a `CreateAction`
for the password format. One can imagine similar actions to derive specialized
outputs like PIN numbers and cryptographic dice. Un-invertible single-use passwords
can be derived by incrementing the child index for a given semantic path.

```json
[
    {
        "@context": "https://schema.org",
        "@type": "WebSite",
        "url": "https://bitcoin.org/en/"
    },
    {
        "@context": "https://schema.org",
        "@type": "CreateAction",
        "name": "Password Derivation",
        "object": {
            "@type": "Thing",
            "name": "Password"
        },
        "result": {
            "@type": "PropertyValueSpecification",
            "valuePattern": "[a-zA-Z0-9]{8,16}",
            "minLength": 8,
            "maxLength": 16,
            "valueRequired": true
        }
    }
]
```


### Physical locations

Semantic paths may specify locations for personal, cryptographic, or other reasons.
Importantly, secrets can be tied to the physical world and vice versa.
For instance the user could store the location of a physical book for a book cipher.


```json
{
    "@context": "https://schema.org",
    "@type": "Place",
    "name": "Prime Park",
    "description": "The book cipher is here.",
    "address": {
        "@type": "PostalAddress",
        "streetAddress": "2048 Diffie Drive",
        "addressLocality": "Alice Springs",
        "addressRegion": "NT",
        "postalCode": "0870",
        "addressCountry": "AU"
    }
}
```

# Keychain design

BIP-Keychain lays the foundation for a semantic key-value store implemented with
hierarchical deterministic wallets. The keychain per se is beyond the scope of this
specification. Nevertheless, in the interest of ensuring spec completeness
we examine the design of keychains built according to this BIP.

## Semantic key, to derivation path, to secret

The application stores a list of semantic keys that can be converted to secrets
according to the following sequence:

```
semantic_path -> I(semantic_path) -> leaf_secret
 = semantic_path -> derivation_path -> leaf_secret
```

In this way keychain applications map semantic derivation paths onto secret values.
We call the rightmost value an _inner leaf secret_ to reflect that fact that it
is a user-facing construct, the deepest value in our map.

We make the following observations:

1. Each semantic path key may be unprotected, protected by a single master password,
or protected by multiple passwords. We call these _outer secrets_.

    > How these _outer secrets_ are derived is an implementation detail.
    > In the spirit of hierarchical deterministic wallets the outer passwords can
    > themselves be semantically and hierarchically derived.

1. If any semantic path is exposed the secret remains secure. The master private
key remains secure.

1. Neither the application client nor the user needs to possess to master private
key in order to _use_ any inner secret.

1. Inner secrets can be derived and transmitted to the application client by
a potentially server-side _key derivation service_ (KDS).

1. The KDS may provide cryptographic proof of the authenticity of its inner secrets
to applications by means of digital signatures, including for instance through 
parent public keys of non-hardened children.

    > "one can derive child public keys of a given parent key without knowing any
    > private key" -BIP-32

1. The inner secrets may be implemented as single-use secrets or rotated by one
or more of the following means:

    1. The application (or KDS) increments the child index
    1. The application (or KDS) nonces the semantic path (see `hmac()`)


# TODO

* [ ] Test vectors
* [ ] Reference implementation
