package pedersen

import (
	"github.com/bwesterb/go-ristretto"
)

// import "crypto/rand"

type Parameters struct {
	g ristretto.Point
	h ristretto.Point
}

func Setup(buf []byte) Parameters {
	var g ristretto.Point
	var h ristretto.Point
	g.DeriveDalek(buf[:len(buf)/2])
	h.DeriveDalek(buf[len(buf)/2:])
	return Parameters{g, h}
}

func GetInsecureParameters() Parameters {
	return Setup([]byte("this is a random string"))
}

type Message struct {
	m ristretto.Scalar
}

func newMessageFromData(buf []byte) Message {
	var m ristretto.Scalar
	m.Derive(buf)
	return Message{m}
}

type BlindingFactor struct {
	r ristretto.Scalar
}

func (r BlindingFactor) Bytes() []byte {
	return r.r.Bytes()
}

func BlindingFactorFromBytes(buf *[32]byte) BlindingFactor {
	var r ristretto.Scalar
	r.SetBytes(buf)
	return BlindingFactor{r}
}

func newBlindingFactorFromData(buf []byte) BlindingFactor {
	var r ristretto.Scalar
	r.Derive(buf)
	return BlindingFactor{r}
}

func randBlindingFactor() BlindingFactor {
	var r ristretto.Scalar
	r.Rand()
	return BlindingFactor{r}
}

func (r *BlindingFactor) Equals(r2 *BlindingFactor) bool {
	return r.r.Equals(&r2.r)
}

type Commitment struct {
	c ristretto.Point
}

func (c Commitment) Bytes() []byte {
	return c.c.Bytes()
}

func (c *Commitment) Equals(c2 *Commitment) bool {
	return c.c.Equals(&c2.c)
}

func CommitmentFromBytes(buf *[32]byte) Commitment {
	var c ristretto.Point
	if !c.SetBytes(buf) {
		panic("invalid point") // TODO: this should return an error
	}
	return Commitment{c}
}

func (p Parameters) commit(data []byte, m Message, r BlindingFactor) Commitment {
	var g ristretto.Point
	var h ristretto.Point

	g.ScalarMult(&p.g, &m.m)
	h.ScalarMult(&p.h, &r.r)
	g.Add(&g, &h)

	return Commitment{g}
}

func (p Parameters) Commit(data []byte) (Commitment, BlindingFactor) {
	m := newMessageFromData(data)
	r := randBlindingFactor()
	comm := p.commit(data, m, r)
	return comm, r
}

func (p Parameters) CommitWithRandomness(data []byte, rand []byte) (Commitment, BlindingFactor) {
	m := newMessageFromData(data)
	r := newBlindingFactorFromData(rand)
	comm := p.commit(data, m, r)
	return comm, r
}

func (p Parameters) Verify(data []byte, c Commitment, r BlindingFactor) bool {
	m := newMessageFromData(data)
	c2 := p.commit(data, m, r)
	return c.Equals(&c2)
}
