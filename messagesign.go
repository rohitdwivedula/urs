// Copyright 2014 The Monero Developers.
// All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

// generateKeyPair generates and stores an ECDSA keypair to a file.
func generateKeyPair() map[string]string {
	// Generate keypairs.
	aKeypair, _ := ecdsa.GenerateKey(btcec.S256(), crand.Reader)
	pubkeyBtcec := btcec.PublicKey{aKeypair.PublicKey.Curve, aKeypair.PublicKey.X, aKeypair.PublicKey.Y}
	keypairBtcec := btcec.PrivateKey{aKeypair.PublicKey, aKeypair.D}

	// Create a map to json marshal
	keypairMap := make(map[string]string)
	keypairMap["pubkey"] = hex.EncodeToString(pubkeyBtcec.SerializeCompressed())
	keypairMap["privkey"] = hex.EncodeToString(keypairBtcec.Serialize())

	// Store the address in case anyone wants to use it for BTC
	pkh, _ := btcutil.NewAddressPubKey(pubkeyBtcec.SerializeCompressed(),
		&chaincfg.MainNetParams)
	keypairMap["address"] = pkh.EncodeAddress()
	return keypairMap
}

func sign(keyPair map[string]string, keyRing map[string]string, message string) string {
	kp, err := ParseKeyPair(keyPair)
	if err != nil {
		return ""
	}
	kr, err := ParseKeyRing(keyRing, kp)
	if err != nil {
		return ""
	}
	ringsig, err := Sign(crand.Reader, kp, kr, []byte(message))
	if Verify(kr, []byte(message), ringsig) {
		return ringsig.ToBase58()
	} else {
		return ""
	}
}

func verify(keyRing map[string]string, message string, signature string) bool {
	kr, err := ParseKeyRing(keyRing, nil)
	if err != nil {
		fmt.Printf("[ERROR GoLang] Could not parse keyring: %v\n", err)
		return false
	}
	decodedSig := &RingSign{nil, nil, nil, nil}
	err = decodedSig.FromBase58(signature)
	if err != nil {
		fmt.Printf("[ERROR GoLang] Could not decode Base58 signature: %v\n", err)
		return false
	}
	return Verify(kr, []byte(message), decodedSig)
}

func main() {

}
