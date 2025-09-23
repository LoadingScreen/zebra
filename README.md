 # ZebraSign: an app for creating and verifying ring signatures
![](zebra_desktop/zebra_head.png)

## What are ring signatures?

A [ring signature](https://en.wikipedia.org/wiki/Ring_signature) is a type of [digital signature](https://en.wikipedia.org/wiki/Digital_signature). Unlike a standard digital signature, which simply proves that someone wrote a particular message, a ring signature contains multiple signatories, one of which is genuine and the rest of which are forged. The reader(s) of the message have no way to verify which of the signatories is the real one.

## What is this useful for?
The ring signature protocol was introduced in a 2001 paper titled ["How to Leak a Secret"](https://doi.org/10.1007%2F3-540-45682-1_32).

Suppose you want to send or publish some information. You want the audience to know that it was
published by someone credible, with access to that information, but you
don't want them to know exactly *which* credible person published it. For example, maybe you want to make an allegation of misconduct--you don't want to put your name on the allegation lest you suffer some retaliation, but if you publish it anonymously you expect it to not be taken seriously.

You can instead publish the information using a ring signature. To do this, you choose
a set of people that you want to include in the "ring": This is the set of
people who, to an observer, *might* plausibly have known the information and wanted to leak it. (In the example, this would be the set of people who might plausibly have the means and motive to make the allegation of misconduct.) Then, you
sign the message using *your* private key, and all of *their* public keys.

Once you publish the information with a ring signature, anyone who knows the
public keys of the ring members (and remember the ring includes you and the other people whose keys you used)
can prove that *someone* in that group signed the message. But they can't prove
*which* person it was.

## Design

ZebraSign is designed with the following principles in mind, in order from most
important to least important:

1. ZebraSign should be a trustworthy implementation of the theory of ring
   signatures. If you observe a signed message, and the app successfully
   verifies the signature, you should be able to feel confident in the
   signature.
2. ZebraSign should be simple to use and hard to misuse. It should be almost
   trivial to create a signature, or import a key. It should be almost
   impossible to leak your private key, or compromise your anonymity within a
   ring.
3. ZebraSign should be implemented as simply as possible, with the minimum set
   of dependencies. The more crucial a piece of code is for providing the
   trustworthiness guarantee, the fewer dependencies it should have.

ZebraSign is a [dioxus](https://dioxuslabs.com) app. This means that the user
interface code can be understood by anyone with knowledge of web programming
and Rust, but the app relies on the operating system's web view rather than a
packaged browser. This improves resource usage somewhat compared to an electon
app.

### Cryptography

ZebraSign's ring signature implementation is based on the algorithm presented
in the book [Zero to Monero: Second
Edition](https://www.getmonero.org/library/Zero-to-Monero-2-0-0.pdf).
We use the [Ristretto group](https://ristretto.group/) as our prime order
group, and in particular the [dalek-cryptography](https://dalek.rs/)
implementation.

Public keys (technically, self-signed certificates) contain the requisite group
element, as well as a signature that verifies that the holder of the key claims
to be associated with the identity provided.

### Storage

ZebraSign uses [age](https://github.com/FiloSottile/age) to encrypt an extremely
simple database of keys. The password for this database is chosen randomly and
stored in the system's keychain. So the operating system will prompt the user
before allowing the database to be unlocked (on app start, or when modifying
the database or using a private key).

We try pretty hard to avoid exposing private keys to other apps. They aren't
stored in memory, except briefly when reading/writing the encrypted database,
or when performing a signing operation, or, of course, when explicitly sending
them to a new machine. When sending data to a remote machine, we use [Magic
Wormhole](https://github.com/magic-wormhole/magic-wormhole.rs) to ensure that
the transfer is encrypted end-to-end. We also use
[secmem-proc](https://github.com/niluxv/secmem-proc) to try to frustrate
attempts at tracing the process or reading core dumps / swap.

## Copyright Information

The icon file `zebra_head.png` is a modification of ["Zebra, Ngorogoro"](https://www.flickr.com/photos/woodlouse/3990713395) by Woodlouse
on Flickr. Unlike the rest of this repository, it is released under a [Creative
Commons Attribution-ShareAlike 2.0 Generic
License](https://creativecommons.org/licenses/by-sa/2.0/).

Some of the code in this repository is released under an MIT license.
Specifically, everything inside of the `age` and `age-core` directories, as
well as the `sign` and `verify` functions in `zebra_crypto/lib.rs`.

Everything else is the copyright of Kurt Brown.

## Running the app
In the root folder, run the following cargo commands to build and run:
```
cargo build --release
cargo run --release
```

To build the webapp, first generate the wasm files:
```
cd zebra_wasm
wasm-pack build
```

Then, run the webapp:
```
cd ..
cd zebra_webapp
npm install
npm run build
npm run start
```
