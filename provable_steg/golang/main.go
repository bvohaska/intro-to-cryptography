package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type dumb_Oracle struct {
	history []string
}

func getKey(size_of_key uint16) ([]byte, error) {

	key := make([]byte, 32)
	n, err := rand.Read(key)

	if uint16(n) != size_of_key {
		return nil, fmt.Errorf("Incorrect number of bytes read from urandom!")
	}
	if err != nil {
		return nil, err
	}

	return key, nil
}

func encryptMessageGCM(key []byte, iv []byte, hiddentext []byte, debug bool) ([]byte, []byte) {

	if iv == nil {
		iv = make([]byte, 12)
		_, err := rand.Read(iv)
		if err != nil {
			panic(err.Error())
		}
	}

	if debug {
		fmt.Printf("Key:\t%x\n", key)
		fmt.Printf("IV:\t%x\n", iv)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, iv, hiddentext, nil)
	if debug {
		fmt.Printf("Ciphertext:\t%x\n", ciphertext)
	}

	return iv, ciphertext
}

func decryptMessageGCM(key []byte, iv []byte, ciphertext []byte, debug bool) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err.Error())
	}

	hiddentext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	if debug {
		fmt.Printf("Key:\t%x\n", key)
		fmt.Printf("IV:\t%x\n", iv)
		fmt.Printf("Hiddentext:\t%s\n", hiddentext)
	}

	return hiddentext, nil
}

func stegPRF(key []byte, output_size_in_bits uint8, input_data []byte) {

}

func main() {

	fmt.Println("Hello World")
	key, _ := getKey(32)
	hiddentext := []byte("Attack at dawn")
	iv, ct := encryptMessageGCM(key, nil, hiddentext, true)
	_, _ = decryptMessageGCM(key, iv, ct, true)
}

// def stegPRF(key: bytes, bits_output: int, data: bytes) -> bitarray:
//     """Given some data, return x bits of PRF_key(data)

//     Args:
//         key (bytes): the PRF key
//         data (bytes): data as input to the PRF

//     Returns:
//         bitarray: bits_output bits of output from the PRF
//     """
//     digest = hashes.Hash(hashes.SHA256())
//     digest.update(key)
//     digest.update(data)
//     out = digest.finalize()

//     ba = bitarray()
//     ba.frombytes(out)

//     return ba[:bits_output]
