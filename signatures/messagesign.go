package signatures

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

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

// sign a message with your keyPair with a keyRing of public keys.
//export SignMV
func SignMV(keyPair_t string, keyRing_t string, m string, v string) string {
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
		return ""
	}
	kr, err := ParseKeyRing(keyRing, kp)
	if err != nil {
		return ""
	}
	ringsig, err := Sign(crand.Reader, kp, kr, []byte(m), []byte(v))
	if err != nil {
		return ""
	}
	if Verify(kr, []byte(m), []byte(v), ringsig) {
		return ringsig.ToBase58()
	} else {
		return ""
	}
}

//export VerifyMV
func VerifyMV(keyRing_t string, m string, v string, signature string) bool {
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

//export Hello
func Hello() string {
	return "Golang says hello!"
}
