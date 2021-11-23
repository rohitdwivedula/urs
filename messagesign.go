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
//export GenerateKeyPair
func GenerateKeyPair() map[string]string {
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

//export FreeString
func FreeString(x *C.char) {
	C.free(unsafe.Pointer(x))
}

// sign a message with your keyPair with a keyRing of public keys.
//export SignMV
func SignMV(keyPair_t string, keyRing_t string, m string, v string) *C.char {
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
		return C.CString(ringsig.ToBase58())
	} else {
		return C.CString("")
	}
}

//export VerifyMV
func VerifyMV(keyRing_t string, m string, v string, signature string) int32 {
	keyRing := make(map[string]string)
	split := strings.Split(keyRing_t, " ")
	for i := 0; i < len(split); i++ {
		keyRing[strconv.Itoa(i)] = split[i]
	}
	kr, err := ParseKeyRing(keyRing, nil)
	if err != nil {
		fmt.Printf("[ERROR GoLang] Could not parse keyring: %v\n", err)
		return 0
	}
	decodedSig := &RingSign{nil, nil, nil, nil, nil, nil}
	err = decodedSig.FromBase58(signature)
	if err != nil {
		fmt.Printf("[ERROR GoLang] Could not decode Base58 signature: %v\n", err)
		return 0
	}
	ver := Verify(kr, []byte(m), []byte(v), decodedSig)
	if ver {
		return 1
	} else {
		return 0
	}
}
