package pedersen

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

type randomnessSource struct {
	reader    io.Reader
	chunkSize int
	chunks    int
}

func newRandomnessSource(rand []byte, chunks int) (*randomnessSource, error) {
	if len(rand) < chunks {
		return nil, fmt.Errorf("not enough data")
	}
	reader := bytes.NewReader(rand)
	chunkSize := len(rand) / chunks
	source := randomnessSource{reader, chunkSize, chunks}
	return &source, nil
}

func (r *randomnessSource) Chunk() []byte {
	if r.chunks <= 0 {
		panic("out of randomness")
	}
	r.chunks -= 1

	chunk := make([]byte, r.chunkSize)
	r.reader.Read(chunk)
	return chunk
}

func FuzzCommitmentVerifies(f *testing.F) {
	f.Add([]byte("<randomness>"), []byte("foo"))
	f.Fuzz(func(t *testing.T, randData []byte, data []byte) {
		rand, err := newRandomnessSource(randData, 2)
		if err != nil {
			t.Skip(err)
		}

		p := Setup(rand.Chunk())
		comm, r := p.CommitWithRandomness(data, rand.Chunk())
		if !p.Verify(data, comm, r) {
			t.Error("didn't verify")
		}
	})

}

func FuzzCommitmentIncorrectDataFails(f *testing.F) {
	f.Add([]byte("<randomness>"), []byte("foo"), []byte("bar"))
	f.Fuzz(func(t *testing.T, randData []byte, data1 []byte, data2 []byte) {
		if bytes.Equal(data1, data2) {
			t.Skip("data should not be equal")
		}

		rand, err := newRandomnessSource(randData, 2)
		if err != nil {
			t.Skip(err)
		}

		p := Setup(rand.Chunk())

		comm, r := p.CommitWithRandomness(data1, rand.Chunk())
		if p.Verify(data2, comm, r) {
			t.Error("data2 should not verify with commitment to data1")
		}
	})
}

func FuzzCommitmentIncorrectBlindingFactorFails(f *testing.F) {
	f.Add([]byte("<randomness>"), []byte("foo"))
	f.Fuzz(func(t *testing.T, randData []byte, data []byte) {
		rand, err := newRandomnessSource(randData, 3)
		if err != nil {
			t.Skip(err)
		}

		p := Setup(rand.Chunk())

		comm1, r1 := p.CommitWithRandomness(data, rand.Chunk())
		comm2, r2 := p.CommitWithRandomness(data, rand.Chunk())
		if r1 == r2 {
			if comm1 != comm2 {
				t.Error("same blinding factor should have same commitment!")
			}
			t.Skip("same blinding factor")
		}
		if p.Verify(data, comm1, r2) || p.Verify(data, comm2, r1) {
			t.Error("commitments should only verify with their blinding factor")
		}
	})
}

func FuzzCommitmentBytesRoundtrip(f *testing.F) {
	f.Add([]byte("<randomness>"), []byte("foo"))
	f.Fuzz(func(t *testing.T, randData []byte, data []byte) {
		rand, err := newRandomnessSource(randData, 2)
		if err != nil {
			t.Skip(err)
		}

		p := Setup(rand.Chunk())
		comm, r := p.CommitWithRandomness(data, rand.Chunk())

		bytes := [32]byte(comm.Bytes())
		comm2 := CommitmentFromBytes(&bytes)
		if !comm.Equals(&comm2) {
			t.Errorf("commitment roundtrip failed: %+v, %+v", comm, comm2)
		}

		bytes = [32]byte(r.Bytes())
		r2 := BlindingFactorFromBytes(&bytes)
		if !r.Equals(&r2) {
			t.Errorf("blinding factor roundtrip failed: %+v, %+v", r, r2)
		}
	})

}
