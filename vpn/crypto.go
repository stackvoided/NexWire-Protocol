package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

func GenerateKeyPair() (*KeyPair, error) {
	var kp KeyPair
	if _, err := io.ReadFull(rand.Reader, kp.Private[:]); err != nil {
		return nil, err
	}
	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64

	curve25519.ScalarBaseMult(&kp.Public, &kp.Private)
	return &kp, nil
}

type ReplayFilter struct {
	mu     sync.Mutex
	lastSeq uint64
	bitmap uint64
}

func (rf *ReplayFilter) Validate(seq uint64) bool {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if seq == 0 {
		return false
	}

	if seq > rf.lastSeq {
		diff := seq - rf.lastSeq
		if diff < 64 {
			rf.bitmap = (rf.bitmap << diff) | 1
		} else {
			rf.bitmap = 1
		}
		rf.lastSeq = seq
		return true
	}

	diff := rf.lastSeq - seq
	if diff >= 64 {
		return false
	}

	if (rf.bitmap & (1 << diff)) != 0 {
		return false
	}

	rf.bitmap |= (1 << diff)
	return true
}

type SessionCipher struct {
	aead       cipher.AEAD
	sendNonce  uint64
	replay     ReplayFilter
	createdAt  int64
}

func NewSessionCipher(sharedSecret []byte) (*SessionCipher, error) {
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("VPN_SESSION_KEY_EXPANSION"))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &SessionCipher{
		aead: aead,
	}, nil
}

func (s *SessionCipher) Encrypt(dst, plaintext []byte, seq uint64) ([]byte, error) {
	var nonce [24]byte
	binary.BigEndian.PutUint64(nonce[16:], seq)

	return s.aead.Seal(dst, nonce[:], plaintext, nil), nil
}

func (s *SessionCipher) Decrypt(dst, ciphertext []byte, seq uint64) ([]byte, error) {
	if !s.replay.Validate(seq) {
		return nil, errors.New("replay attack detected or packet too old")
	}

	var nonce [24]byte
	binary.BigEndian.PutUint64(nonce[16:], seq)

	return s.aead.Open(dst, nonce[:], ciphertext, nil)
}
