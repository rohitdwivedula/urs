package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

// generates and return an ECDSA keypair.
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

//export freeString
func freeString(x *C.char) {
	C.free(unsafe.Pointer(x))
}

// sign a message with your keyPair with a keyRing of public keys.
//export sign
func sign(keyPair_t string, keyRing_t string, m string, v string) *C.char {
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

	kp, err := ParseKeyPair(keyPair)
	if err != nil {
		return C.CString("")
	}
	kr, err := ParseKeyRing(keyRing, kp)
	if err != nil {
		return C.CString("")
	}
	ringsig, err := Sign(crand.Reader, kp, kr, []byte(m), []byte(v))
	if err != nil {
		return C.CString("")
	}
	if Verify(kr, []byte(m), []byte(v), ringsig) {
		fmt.Printf("%v", ringsig.ToBase58())
		return C.CString(ringsig.ToBase58())
	} else {
		return C.CString("")
	}
}

//export verify
func verify(keyRing_t string, m string, v string, signature string) bool {
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
	decodedSig := &RingSign{nil, nil, nil, nil, nil, nil}
	err = decodedSig.FromBase58(signature)
	if err != nil {
		fmt.Printf("[ERROR GoLang] Could not decode Base58 signature: %v\n", err)
		return false
	}
	return Verify(kr, []byte(m), []byte(v), decodedSig)
}

func main() {
	s := sign(
		"1NBN9d4pZutCykB3Why5f3V7hG27EbcqKb 4fb0b355ad56c1d19ebb30591a036dfb6a2c20d9836b22c23dc521ea53e08cd4 02dcdb96d05d6cd36ce7014a69ebce8b48f8d7de46ce3bfa99482af65284697e13",
		"024627032575180c2773b3eedd3a163dc2f3c6c84f9d0a1fc561a9578a15e6d0e3 02b266b2c32ba5fc8d203c8f3e65e50480dfc10404ed089bad5f9ac5a45ffa4251 031ea759e3401463b82e2132535393076dde89bf2af7fc550f0793126669ffb5cd",
		"pollID", "myVoteIs10",
	)
	fmt.Printf("SINATURE: %v\n", s)
}
