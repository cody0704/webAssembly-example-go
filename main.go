package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"io"
	"log"
	"math/big"

	"fmt"

	"syscall/js"

	"golang.org/x/crypto/bn256"
)

func main() {
	js.Global().Set("demo", js.FuncOf(demo))
}

func demo(thie js.Value, args []js.Value) interface{} {

	m := args[0].String()

	s, _ := rand.Int(rand.Reader, bn256.Order)
	p, _ := rand.Int(rand.Reader, bn256.Order)

	// Then each party calculates g₁ and g₂ times their private value.
	P := new(bn256.G1).ScalarBaseMult(p)

	// //Setup, system parameters generation
	pub := new(bn256.G1).ScalarMult(P, s)

	// //Extract, key calculation
	qid := string2Hash("Cody", sha256.New())
	did := new(bn256.G2).ScalarMult(qid, s)

	r, _ := rand.Int(rand.Reader, bn256.Order)
	u := new(bn256.G1).ScalarMult(P, r)

	gid := bn256.Pair(pub, qid)
	gidr := new(bn256.GT).ScalarMult(gid, r)

	z := gidr

	temp := bn256.Pair(u, did)

	if encrypted, err := encrypt([]byte(m), z.Marshal()[:32]); err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("CIPHER KEY: %s\n", string(z.Marshal()[:32]))
		fmt.Printf("ENCRYPTED: %s\n", encrypted)

		if decrypted, err := decrypt(encrypted, temp.Marshal()[:32]); err != nil {
			log.Println(err)
		} else {
			log.Printf("DECRYPTED: %s\n", decrypted)
			return decrypted
		}
	}

	return "Decrypt Failed"
}

func string2Hash(s string, h hash.Hash) (n *bn256.G2) {
	h.Reset()
	if _, err := h.Write([]byte(s)); err != nil {
		fmt.Println("ERROR")
	}

	data := fmt.Sprintf("%d%d%d%d",
		binary.BigEndian.Uint64(h.Sum([]byte{})[0:8]),
		binary.BigEndian.Uint64(h.Sum([]byte{})[8:16]),
		binary.BigEndian.Uint64(h.Sum([]byte{})[16:24]),
		binary.BigEndian.Uint64(h.Sum([]byte{})[24:32]))

	b, _ := new(big.Int).SetString(data, 10)
	return new(bn256.G2).ScalarBaseMult(b)
}

func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func aesCBCEncrypt(rawData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	blockSize := block.BlockSize()

	rawData = pkcs7Padding(rawData, blockSize)
	cipherText := make([]byte, blockSize+len(rawData))
	iv := cipherText[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[blockSize:], rawData)

	return cipherText, nil
}

func aesCBCDncrypt(encryptData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		panic("ciphertext too short")
	}
	iv := encryptData[:blockSize]
	encryptData = encryptData[blockSize:]

	// CBC mode always works in whole blocks.
	if len(encryptData)%blockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptData, encryptData)

	encryptData = pkcs7UnPadding(encryptData)
	return encryptData, nil
}

func encrypt(rawData, key []byte) (string, error) {
	data, err := aesCBCEncrypt(rawData, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func decrypt(rawData string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(rawData)
	if err != nil {
		return "", err
	}
	dnData, err := aesCBCDncrypt(data, key)
	if err != nil {
		return "", err
	}
	return string(dnData), nil
}
