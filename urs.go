// Copyright 2014 Hein Meling and Haibin Zhang. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.
// Additional coding Copyright 2014 The Monero Developers.

// Package urs implements Unique Ring Signatures, as defined in
// short version: http://csiflabs.cs.ucdavis.edu/~hbzhang/romring.pdf
// full version: http://eprint.iacr.org/2012/577.pdf
package main

// References:
//   [NSA]: Suite B implementer's guide to FIPS 186-3,
//     http://www.nsa.gov/ia/_files/ecdsa.pdf
//   [SECG]: SECG, SEC1
//     http://www.secg.org/download/aid-780/sec1-v2.pdf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"sync"
)

// PublicKeyRing is a list of public keys.
type PublicKeyRing struct {
	Ring []ecdsa.PublicKey
}

// NewPublicKeyRing creates a new public key ring.
// All keys added to the ring must use the same curve.
func NewPublicKeyRing(cap uint) *PublicKeyRing {
	return &PublicKeyRing{make([]ecdsa.PublicKey, 0, cap)}
}

// Add adds a public key, pub to the ring.
// All keys added to the ring must use the same curve.
func (r *PublicKeyRing) Add(pub ecdsa.PublicKey) {
	r.Ring = append(r.Ring, pub)
}

// Less determines which of two []ecdsa.PublicKey X values is smaller; if they are
// the same, evaluate the Y values instead.
func (r *PublicKeyRing) Less(i, j int) bool {
	var isISmaller bool

	iX := r.Ring[i].X
	jX := r.Ring[j].X
	cmp := iX.Cmp(jX)

	if cmp != 0 {
		isISmaller = (cmp == -1) // X equivalence
	} else { // Use Y for less if X is equivalent
		iY := r.Ring[i].Y
		jY := r.Ring[j].Y
		cmp = iY.Cmp(jY)
		isISmaller = (cmp == -1)
	}

	return isISmaller
}

// Swap swaps two []ecdsa.PublicKey values.
func (r *PublicKeyRing) Swap(i, j int) {
	r.Ring[i], r.Ring[j] = r.Ring[j], r.Ring[i]
}

// Len returns the length of ring.
func (r *PublicKeyRing) Len() int {
	return len(r.Ring)
}

// Bytes returns the public key ring as a byte slice.
func (r *PublicKeyRing) Bytes() (b []byte) {
	for _, pub := range r.Ring {
		b = append(b, pub.X.Bytes()...)
		b = append(b, pub.Y.Bytes()...)
	}
	return
}

func PubKeyToString(k ecdsa.PublicKey) string {
	return fmt.Sprintf("X(%s)\nY(%s)\n", k.X, k.Y)
}

var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// GenerateKey generates a public and private key pair.
func GenerateKey(c elliptic.Curve, rand io.Reader) (priv *ecdsa.PrivateKey, err error) {
	k, err := randFieldElement(c, rand)
	if err != nil {
		return
	}

	priv = new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.

type RingSign struct {
	X, Y   *big.Int
	Xp, Yp *big.Int
	C, T   []*big.Int
}

// this is just for debugging; we probably don't want this for anything else
func (k *RingSign) String() string {
	var buf bytes.Buffer
	for i := 0; i < len(k.C); i++ {
		buf.WriteString(fmt.Sprintf("C[%d]: ", i))
		buf.WriteString(k.C[i].String())
		buf.WriteString("\n")
		buf.WriteString(fmt.Sprintf("T[%d]: ", i))
		buf.WriteString(k.T[i].String())
		buf.WriteString("\n")
	}
	return fmt.Sprintf("URS:\nX=%s\nY=%s\nXp=%s\nYp=%s\n%s", k.X, k.Y, k.Xp, k.Yp, buf.String())
}

// FromBase58 returns a ring signature from a Base58 string, to the RingSign
// struct.
func (k *RingSign) FromBase58(sig string) error {

	k.X = nil
	k.Y = nil
	k.Xp = nil
	k.Yp = nil
	k.C = nil
	k.T = nil

	// [0] --> X
	// [1] --> Y
	// [2] --> Xp
	// [3] --> Yp
	// [4] --> C
	// [5] --> T

	stringArray := strings.Split(sig[1:], "+")

	if len(stringArray) != 6 {
		err := errors.New("Failure to parse string signature for Base58 encoded" +
			" ring signature! The signature did not contain 4 elements split by " +
			"+'s.")
		return err
	}

	cArray := strings.Split(stringArray[4], "&")
	tArray := strings.Split(stringArray[5], "&")

	XB58 := Base58(stringArray[0])
	k.X = XB58.Base582Big()

	YB58 := Base58(stringArray[1])
	k.Y = YB58.Base582Big()

	XpB58 := Base58(stringArray[2])
	k.Xp = XpB58.Base582Big()

	YpB58 := Base58(stringArray[3])
	k.Yp = YpB58.Base582Big()

	for i, c := range cArray {
		if i == len(cArray)-1 {
			continue
		}

		cB58 := Base58(c)
		k.C = append(k.C, cB58.Base582Big())
	}

	for i, t := range tArray {
		if i == len(cArray)-1 {
			continue
		}

		tB58 := Base58(t)
		k.T = append(k.T, tB58.Base582Big())
	}

	if (k.X == nil) || (k.Y == nil) || (k.Xp == nil) || (k.Yp == nil) || (k.C == nil) || (k.T == nil) {
		err := errors.New("Failure to parse string signature for Base58 encoded" +
			" ring signature!")
		return err
	}

	return nil
}

// ToBase58 returns a ring signature as a Base58 string.
func (k *RingSign) ToBase58() string {
	var buffer bytes.Buffer
	buffer.WriteString("1") // Version
	buffer.WriteString(string(Big2Base58(k.X)))
	buffer.WriteString("+")
	buffer.WriteString(string(Big2Base58(k.Y)))
	buffer.WriteString("+")
	buffer.WriteString(string(Big2Base58(k.Xp)))
	buffer.WriteString("+")
	buffer.WriteString(string(Big2Base58(k.Yp)))
	buffer.WriteString("+")

	for _, c := range k.C {
		buffer.WriteString(string(Big2Base58(c)))
		buffer.WriteString("&")
	}

	buffer.WriteString("+")

	for _, t := range k.T {
		buffer.WriteString(string(Big2Base58(t)))
		buffer.WriteString("&")
	}

	return buffer.String()
}

func hashG(c elliptic.Curve, m []byte) (hx, hy *big.Int) {
	h := sha256.New()
	h.Write(m)
	d := h.Sum(nil)
	hx, hy = c.ScalarBaseMult(d) // g^H'()
	return
}

// hashAllq hashes all the provided inputs using sha256.
// This corresponds to hashq() or H'() over Zq
func hashAllq(mvR []byte, hsx, hsy, hspx, hspy *big.Int, ax, ay, bx, by, bpx, bpy []*big.Int) (hash *big.Int) {
	h := sha256.New()
	h.Write(mvR)
	h.Write(hsx.Bytes())
	h.Write(hsy.Bytes())
	h.Write(hspx.Bytes())
	h.Write(hspy.Bytes())
	for i := 0; i < len(ax); i++ {
		h.Write(ax[i].Bytes())
		h.Write(ay[i].Bytes())
		h.Write(bx[i].Bytes())
		h.Write(by[i].Bytes())
		h.Write(bpx[i].Bytes())
		h.Write(bpy[i].Bytes())
	}
	hash = new(big.Int).SetBytes(h.Sum(nil))
	return
}

// hashAllq hashes all the provided inputs using sha256.
// This corresponds to hashq() or H'() over Zq

// Sign signs an arbitrary length message (which should NOT be the hash of a
// larger message) using the private key, priv and the public key ring, R.
// It returns the signature as a struct of type RingSign.
// The security of the private key depends on the entropy of rand.
// The public keys in the ring must all be using the same curve.
func Sign(rand io.Reader,
	priv *ecdsa.PrivateKey,
	R *PublicKeyRing,
	m []byte,
	v []byte) (rs *RingSign, err error) {

	sort.Sort(R)

	s := R.Len()
	ax := make([]*big.Int, s, s)
	ay := make([]*big.Int, s, s)
	bx := make([]*big.Int, s, s)
	by := make([]*big.Int, s, s)
	bpx := make([]*big.Int, s, s)
	bpy := make([]*big.Int, s, s)
	c := make([]*big.Int, s, s)
	t := make([]*big.Int, s, s)
	pub := priv.PublicKey
	curve := pub.Curve
	N := curve.Params().N

	mR := append(m, R.Bytes()...)
	mv := append(m, v...)
	mvR := append(mv, R.Bytes()...)
	hx, hy := hashG(curve, mR)    // H(mR)
	hpx, hpy := hashG(curve, mvR) // H(mvR)

	var id int
	var wg sync.WaitGroup
	sum := new(big.Int).SetInt64(0)
	for j := 0; j < s; j++ {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			c[j], err = randFieldElement(curve, rand)
			if err != nil {
				return
			}
			t[j], err = randFieldElement(curve, rand)
			if err != nil {
				return
			}

			if R.Ring[j] == pub {
				id = j
				rb := t[j].Bytes()
				ax[id], ay[id] = curve.ScalarBaseMult(rb)         // g^r
				bx[id], by[id] = curve.ScalarMult(hx, hy, rb)     // H(mR)^r
				bpx[id], bpy[id] = curve.ScalarMult(hpx, hpy, rb) // H(mvR)^r
			} else {
				ax1, ay1 := curve.ScalarBaseMult(t[j].Bytes())                       // g^tj
				ax2, ay2 := curve.ScalarMult(R.Ring[j].X, R.Ring[j].Y, c[j].Bytes()) // yj^cj
				ax[j], ay[j] = curve.Add(ax1, ay1, ax2, ay2)

				w := new(big.Int)
				w.Mul(priv.D, c[j])
				w.Add(w, t[j])
				w.Mod(w, N)
				bx[j], by[j] = curve.ScalarMult(hx, hy, w.Bytes())     // H(mR)^(xi*cj+tj)
				bpx[j], bpy[j] = curve.ScalarMult(hpx, hpy, w.Bytes()) // H(mvR)^(xi*cj+tj)
				// TODO may need to lock on sum object.
				sum.Add(sum, c[j]) // Sum needed in Step 3 of the algorithm
			}
		}(j)
	}
	wg.Wait()
	// Step 3, part 1: cid = H(m,R,{a,b}) - sum(cj) mod N
	hsx, hsy := curve.ScalarMult(hx, hy, priv.D.Bytes())     // Step 4: H(mR)^xi
	hspx, hspy := curve.ScalarMult(hpx, hpy, priv.D.Bytes()) // Step 4: H(mvR)^xi

	hashmvRabbp := hashAllq(mvR, hsx, hsy, hspx, hspy, ax, ay, bx, by, bpx, bpy)
	// hashmRab := hashAllqc(curve, mR, ax, ay, bx, by)
	c[id].Sub(hashmvRabbp, sum)
	c[id].Mod(c[id], N)

	// Step 3, part 2: tid = ri - cid * xi mod N
	cx := new(big.Int)
	cx.Mul(priv.D, c[id])
	t[id].Sub(t[id], cx) // here t[id] = ri (initialized inside the for-loop above)
	t[id].Mod(t[id], N)

	return &RingSign{hsx, hsy, hspx, hspy, c, t}, nil
}

// Verify verifies the signature in rs of m using the public key ring, R. Its
// return value records whether the signature is valid.
func Verify(R *PublicKeyRing, m []byte, v []byte, rs *RingSign) bool {
	sort.Sort(R)

	s := R.Len()
	if s == 0 {
		return false
	}
	c := R.Ring[0].Curve
	N := c.Params().N
	x, y := rs.X, rs.Y
	xp, yp := rs.Xp, rs.Yp

	if x.Sign() == 0 || y.Sign() == 0 {
		return false
	}
	if x.Cmp(N) >= 0 || y.Cmp(N) >= 0 {
		return false
	}
	if !c.IsOnCurve(x, y) { // Is tau_{1} (x,y) on the curve
		return false
	}

	if xp.Sign() == 0 || yp.Sign() == 0 {
		return false
	}
	if xp.Cmp(N) >= 0 || yp.Cmp(N) >= 0 {
		return false
	}
	if !c.IsOnCurve(xp, yp) { // Is tau_{2} (x,y) on the curve
		return false
	}

	mR := append(m, R.Bytes()...)
	mv := append(m, v...)
	mvR := append(mv, R.Bytes()...)
	hx, hy := hashG(c, mR)    // H(mR)
	hpx, hpy := hashG(c, mvR) // H(mvR)

	sum := new(big.Int).SetInt64(0)
	ax := make([]*big.Int, s, s)
	ay := make([]*big.Int, s, s)
	bx := make([]*big.Int, s, s)
	by := make([]*big.Int, s, s)
	bpx := make([]*big.Int, s, s)
	bpy := make([]*big.Int, s, s)
	var wg sync.WaitGroup
	for j := 0; j < s; j++ {
		// Check that cj,tj is in range [0..N]
		if rs.C[j].Cmp(N) >= 0 || rs.T[j].Cmp(N) >= 0 {
			return false
		}
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			cb := rs.C[j].Bytes()
			tb := rs.T[j].Bytes()
			ax1, ay1 := c.ScalarBaseMult(tb)                       // g^tj
			ax2, ay2 := c.ScalarMult(R.Ring[j].X, R.Ring[j].Y, cb) // yj^cj
			ax[j], ay[j] = c.Add(ax1, ay1, ax2, ay2)
			bx1, by1 := c.ScalarMult(hx, hy, tb) // H(mR)^tj
			bx2, by2 := c.ScalarMult(x, y, cb)   // tau_{1}^cj
			bx[j], by[j] = c.Add(bx1, by1, bx2, by2)
			bpx1, bpy1 := c.ScalarMult(hpx, hpy, tb) // H(mvR)^tj
			bpx2, bpy2 := c.ScalarMult(xp, yp, cb)   // tau_{2}^cj
			bpx[j], bpy[j] = c.Add(bpx1, bpy1, bpx2, bpy2)
		}(j)
		sum.Add(sum, rs.C[j])
	}
	wg.Wait()
	hashmvRabbp := hashAllq(mvR, x, y, xp, yp, ax, ay, bx, by, bpx, bpy)
	// hashmRab := hashAllqc(c, mR, ax, ay, bx, by)
	hashmvRabbp.Mod(hashmvRabbp, N)
	sum.Mod(sum, N)
	return sum.Cmp(hashmvRabbp) == 0
}
