// Copyright 2014 The Monero Developers.
// All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package main

import (
	"C"
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)
import "strconv"

// generateKeyPair generates and stores an ECDSA keypair to a file.
//export generateKeyPair
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

//export sign
func sign(keyPair_t string, keyRing_t string, message string) string {
	keyPair := make(map[string]string)
	keyRing := make(map[string]string)

	split1 := strings.Split(keyPair_t, " ")
	split2 := strings.Split(keyRing_t, " ")

	keyPair["address"] = split1[0]
	keyPair["privkey"] = split1[1]
	keyPair["pubkey"] = split1[2]

	for i := 0; i < len(split2); i++ {
		keyRing[strconv.Itoa(i)] = split2[i]
	}

	fmt.Printf("[SIGN] Keypair: %v\n\n", keyPair)
	fmt.Printf("[SIGN] Keyring: %v\n\n", keyRing)

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

//export verify
func verify(keyRing_t string, message string, signature string) bool {
	keyRing := make(map[string]string)
	split := strings.Split(keyRing_t, " ")
	for i := 0; i < len(split); i++ {
		keyRing[strconv.Itoa(i)] = split[i]
	}

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
	s := sign(
		"1NBN9d4pZutCykB3Why5f3V7hG27EbcqKb 4fb0b355ad56c1d19ebb30591a036dfb6a2c20d9836b22c23dc521ea53e08cd4 02dcdb96d05d6cd36ce7014a69ebce8b48f8d7de46ce3bfa99482af65284697e13",
		"024627032575180c2773b3eedd3a163dc2f3c6c84f9d0a1fc561a9578a15e6d0e3 02b266b2c32ba5fc8d203c8f3e65e50480dfc10404ed089bad5f9ac5a45ffa4251 031ea759e3401463b82e2132535393076dde89bf2af7fc550f0793126669ffb5cd",
		"ROHIT",
	)
	fmt.Printf("SINATURE: %v\n", s)
}
