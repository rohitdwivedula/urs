// Copyright 2014 The Monero Developers. All rights reserved.
// Additions by Rohit Dwivedula
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package signatures

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/btcsuite/btcd/btcec"
)

// CmpPubKey compares two pubkeys and returns true if they are the same, else
// false. WARNING: Assumes the curves are equivalent!
func CmpPubKey(i, j *ecdsa.PublicKey) bool {
	if i.X.Cmp(j.X) != 0 {
		return false
	}

	if i.Y.Cmp(j.Y) != 0 {
		return false
	}

	return true
}

// keyInKeyRing checks if a pubkey exists in the keyring.
func (kr *PublicKeyRing) keyInKeyRing(k *ecdsa.PublicKey) bool {
	for _, key := range kr.Ring {
		if CmpPubKey(k, &key) {
			return true
		}
	}
	return false
}

// ParseKeyRing reads a key ring of public keys as a mapping and also
// inserts the pubkey of a keypair if it's not already present (handles
// bug in URS implementation).
func ParseKeyRing(keyMap map[string]string, kp *ecdsa.PrivateKey) (*PublicKeyRing, error) {
	kr := NewPublicKeyRing(uint(len(keyMap)))

	// Stick the pubkeys into the keyring as long as it doesn't belong to the
	// keypair given.
	for i := 0; i < len(keyMap); i++ {
		pkBytes, errDecode := hex.DecodeString(keyMap[strconv.Itoa(i)])
		if errDecode != nil {
			decodeError := errors.New("decode error: Couldn't decode hex.")
			return nil, decodeError
		}

		pubkey, errParse := btcec.ParsePubKey(pkBytes, btcec.S256())
		if errParse != nil {
			return nil, errParse
		}

		ecdsaPubkey := ecdsa.PublicKey{pubkey.Curve, pubkey.X, pubkey.Y}

		if kp == nil || !CmpPubKey(&kp.PublicKey, &ecdsaPubkey) {
			kr.Add(ecdsaPubkey)
		} else {
			kr.Add(kp.PublicKey)
		}
	}

	// Stick the keypair in if it's missing.
	if kp != nil && !kr.keyInKeyRing(&kp.PublicKey) {
		kr.Add(kp.PublicKey)
	}

	return kr, nil
}

// ParseKeyPair reads an ECDSA keypair a file from a mapping and checks if a pubkey is in the
// keyring and, if not, appends it to the keyring.
func ParseKeyPair(keyMap map[string]string) (*ecdsa.PrivateKey, error) {
	var pubkey *ecdsa.PublicKey
	var privkey *ecdsa.PrivateKey
	privBytes, errDecode := hex.DecodeString(keyMap["privkey"])
	if errDecode != nil {
		decodeError := errors.New("decode error: Couldn't decode hex for privkey.")
		return nil, decodeError
	}

	// PrivKeyFromBytes doesn't return an error, so this could possibly be ugly.
	privkeyBtcec, _ := btcec.PrivKeyFromBytes(btcec.S256(), privBytes)

	pubBytes, errDecode := hex.DecodeString(keyMap["pubkey"])
	if errDecode != nil {
		decodeError := errors.New("decode error: Couldn't decode hex for privkey.")
		return nil, decodeError
	}

	pubkeyBtcec, errParse := btcec.ParsePubKey(pubBytes, btcec.S256())
	if errParse != nil {
		return nil, errParse
	}

	// Assign the things to return
	pubkey = &ecdsa.PublicKey{pubkeyBtcec.Curve,
		pubkeyBtcec.X,
		pubkeyBtcec.Y}

	privkey = &ecdsa.PrivateKey{*pubkey, privkeyBtcec.D}
	return privkey, nil
}
