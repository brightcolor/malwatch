package quarantine

import "testing"

// decoderState is a second, independent implementation of the ZipCrypto key
// schedule described at the top of zipcrypt.go - written from that
// description rather than by calling into zipcrypt.go's own types, so a
// mistyped seed or a swapped operator in the production code shows up as a
// mismatch here instead of a test that only checks itself.
//
// It uses the bitwise CRC-32 update (eight rounds of shift-and-XOR) where
// zipcrypt.go uses hash/crc32's lookup table - two different techniques for
// the same polynomial, so agreement between them is a real check.
type decoderState struct {
	a, b, c uint32
}

func newDecoderState(password string) *decoderState {
	d := &decoderState{a: 0x12345678, b: 0x23456789, c: 0x34567890}
	for i := 0; i < len(password); i++ {
		d.absorb(password[i])
	}
	return d
}

func (d *decoderState) absorb(plain byte) {
	d.a = crc32Step(d.a, plain)
	d.b = (d.b+(d.a&0xff))*134775813 + 1
	d.c = crc32Step(d.c, byte(d.b>>24))
}

func crc32Step(key uint32, b byte) uint32 {
	x := (key ^ uint32(b)) & 0xff
	for i := 0; i < 8; i++ {
		if x&1 != 0 {
			x = (x >> 1) ^ 0xEDB88320
		} else {
			x >>= 1
		}
	}
	return x ^ (key >> 8)
}

// mask derives the next keystream byte from the current key state, the same
// quantity zipcrypt.go's decryptByte computes.
func (d *decoderState) mask() byte {
	t := uint16(d.c) | 2
	return byte((uint32(t) * uint32(t^1)) >> 8)
}

// decrypt reverses one byte of ZipCrypto ciphertext and advances the key
// state on the recovered plaintext, per APPNOTE.TXT 6.3.4.
func (d *decoderState) decrypt(cipher byte) byte {
	plain := cipher ^ d.mask()
	d.absorb(plain)
	return plain
}

func TestZipCryptoRoundTripsThroughAnIndependentDecoder(t *testing.T) {
	password := "infected"
	plain := []byte("quarantined sample - not a real PHP payload, just round-trip bytes")

	prod := newZipKeys(password)
	cipher := make([]byte, len(plain))
	for i, b := range plain {
		cipher[i] = prod.encryptByte(b)
	}

	dec := newDecoderState(password)
	got := make([]byte, len(cipher))
	for i, b := range cipher {
		got[i] = dec.decrypt(b)
	}

	if string(got) != string(plain) {
		t.Fatalf("independent decoder got %q, want %q", got, plain)
	}
}

func TestZipCryptoTheWrongPasswordDoesNotRecoverThePlaintext(t *testing.T) {
	plain := []byte("quarantined sample bytes for the wrong-password check")

	prod := newZipKeys("infected")
	cipher := make([]byte, len(plain))
	for i, b := range plain {
		cipher[i] = prod.encryptByte(b)
	}

	dec := newDecoderState("wrong-password")
	got := make([]byte, len(cipher))
	for i, b := range cipher {
		got[i] = dec.decrypt(b)
	}

	if string(got) == string(plain) {
		t.Fatal("decoding with the wrong password recovered the original plaintext")
	}
}

func TestZipCryptoHeaderCheckByteIsTheHighByteOfTheCRC(t *testing.T) {
	// The convention Export relies on: the header's last byte, once
	// decrypted, equals the high byte of the file's CRC-32. Exercised here
	// directly against the key schedule, without going through a zip file.
	password := "infected"
	const crcHighByte = 0xAB

	prod := newZipKeys(password)
	header := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, crcHighByte}
	cipher := make([]byte, len(header))
	for i, b := range header {
		cipher[i] = prod.encryptByte(b)
	}

	dec := newDecoderState(password)
	var lastPlain byte
	for _, b := range cipher {
		lastPlain = dec.decrypt(b)
	}
	if lastPlain != crcHighByte {
		t.Fatalf("decrypted header check byte = %#x, want %#x", lastPlain, crcHighByte)
	}
}
