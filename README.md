Unique Ring Signatures (URS)
============================

[URS](http://web.archive.org/web/20170810111724/https://csiflabs.cs.ucdavis.edu/~hbzhang/romring.pdf) can be used to sign plaintext or binaries anonymously 
(among a group of known users). That is a user can sign a 
message, hiding among a group of known/registered users, 
that prevents the verifier from revealing the signer's 
identity other than knowing that it is in the set of 
registered users. The size of the set of registered users 
is flexible. Increasing this number slows down signing and 
verifying linearly, and also increases the size of the 
signatures linearly.

When in default (unique) mode, signatures are generated 
with the prefix '1' and contain immutable Hx, Hy values 
as the first two bigints in the signature. These are 
immutable per message and private key. That is, any 
single message signed with the same private key and 
keyring will always generate the same Hx, Hy values, so 
for this single message you can identify if multiple 
members of the keyring have signed (but not which one).

Signature blinding has also been implemented. Blind 
signatures are prefixed with '2'. While blind signatures 
lose their Hx, Hy uniqueness, they use an ephemeral key 
to generate that signature that is afterwards discarded. 
This will prevents someone in the future from being able 
to identify which member of the ring signaturesigned the
message, even if all private keys for the public keys in 
the keyring are later revealed.

For more information on signature blinding, refer to 
[this link](https://download.wpsoftware.net/bitcoin/wizardry/ringsig-blinding.txt).

## Commands
For building a C shared library use `go build -buildmode=c-shared -o urs.so`.
For creating the `AAR` for Android use a command that looks something like: `ANDROID_HOME=/home/ardula/Android/Sdk/ ANDROID_NDK_HOME=/home/ardula/Android/Sdk/android-ndk gomobile bind -target android -v` (make sure to go into the `signatures` directory before running this.)

## Requirements
[Go](http://golang.org) 1.2 or newer.

## Acknowledgements
- This is a fork of [Monero Project - URS](https://github.com/monero-project/urs/)
- Andytoshi and Gmaxwell for their signature blinding scheme.
- Conformal Systems for generating the btcec lib, so that secp256k1 could be used.
- Hein Meling for the initial library for the ring signatures.
