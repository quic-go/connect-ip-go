package utils

import (
	"encoding/binary"
	"log"
	"math/rand/v2"
)

func RandomBytes(n int) []byte {
	var seed [32]byte
	binary.BigEndian.PutUint64(seed[:], uint64(n))
	rng := rand.NewChaCha8(seed)
	data := make([]byte, n)
	_, err := rng.Read(data)
	if err != nil {
		log.Fatalf("failed to generate random bytes: %v", err)
	}
	return data
}
