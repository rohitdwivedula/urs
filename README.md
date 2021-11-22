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

## Commands [C++ Shared Library]
- For building a C shared library use `go build -buildmode=c-shared -o urs.so` (see `go_build_c.sh`)
- For creating the `aar/jar` for Android use the `master` branch.

## Sample Code
```golang
package main

import (
	"fmt"
)

func main() {
	s := SignMV(
		"1NBN9d4pZutCykB3Why5f3V7hG27EbcqKb 4fb0b355ad56c1d19ebb30591a036dfb6a2c20d9836b22c23dc521ea53e08cd4 02dcdb96d05d6cd36ce7014a69ebce8b48f8d7de46ce3bfa99482af65284697e13",
		"024627032575180c2773b3eedd3a163dc2f3c6c84f9d0a1fc561a9578a15e6d0e3 02b266b2c32ba5fc8d203c8f3e65e50480dfc10404ed089bad5f9ac5a45ffa4251 031ea759e3401463b82e2132535393076dde89bf2af7fc550f0793126669ffb5cd",
		"pollID", "myVoteIs10",
	)
	fmt.Printf("SINATURE: %v\n", s)
}
```

## Requirements
[Go](http://golang.org) 1.2 or newer.

## Acknowledgements
- This is a fork of [Monero Project - URS](https://github.com/monero-project/urs/)
- Andytoshi and Gmaxwell for their signature blinding scheme.
- Conformal Systems for generating the btcec lib, so that secp256k1 could be used.
- Hein Meling for the initial library for the ring signatures.
