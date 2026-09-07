package quarantine

// This file implements ZipCrypto, the "traditional" encryption from
// PKWARE's APPNOTE.TXT (section 6.3.4), by hand - the standard library has
// no zip encryption of any kind.
//
// This is containment, not confidentiality. ZipCrypto is broken: with a
// little known plaintext it falls in seconds, and that is fine here. The
// point of DefaultPassword is that every unpacker on earth already knows
// it, so a sample can be handed to a scanner or a colleague without it
// opening on a stray double-click or being re-flagged by whatever scans the
// outgoing mail. Nothing quarantined this way should be treated as secret.

import "hash/crc32"

// zipKeys is ZipCrypto's mutable state: three 32-bit values seeded from the
// password and then updated one plaintext byte at a time, so byte N of the
// stream depends on every byte before it.
type zipKeys struct {
	key0, key1, key2 uint32
}

// newZipKeys seeds the key schedule from password, byte by byte - the same
// operation every later byte of plaintext also performs.
func newZipKeys(password string) *zipKeys {
	k := &zipKeys{key0: 0x12345678, key1: 0x23456789, key2: 0x34567890}
	for i := 0; i < len(password); i++ {
		k.updateKeys(password[i])
	}
	return k
}

// updateKeys folds one plaintext byte into all three keys, per APPNOTE.TXT
// 6.3.4: key0 and key2 each take one step of ordinary CRC-32, key1 is a
// linear congruential generator stirred by key0.
func (k *zipKeys) updateKeys(plain byte) {
	k.key0 = crc32.IEEETable[byte(k.key0)^plain] ^ (k.key0 >> 8)
	k.key1 += k.key0 & 0xff
	k.key1 = k.key1*134775813 + 1
	k.key2 = crc32.IEEETable[byte(k.key2)^byte(k.key1>>24)] ^ (k.key2 >> 8)
}

// decryptByte derives the next keystream byte from the current key state.
// The name is APPNOTE.TXT's own: the same byte masks a plaintext byte going
// in as it unmasks a ciphertext byte coming out, which is what lets
// encryptByte below use it for encryption.
func (k *zipKeys) decryptByte() byte {
	temp := uint16(k.key2) | 2
	return byte((uint32(temp) * uint32(temp^1)) >> 8)
}

// encryptByte enciphers one plaintext byte and advances the key schedule on
// that plaintext. The order matters: the schedule has to track plaintext,
// not ciphertext, or the next call would derive the wrong mask.
func (k *zipKeys) encryptByte(plain byte) byte {
	mask := k.decryptByte()
	k.updateKeys(plain)
	return plain ^ mask
}
