package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

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

var encoded = make(map[int]string)

func collect(w http.ResponseWriter, req *http.Request) {

	req.ParseForm()
	data := req.FormValue("data")
	parcel := req.FormValue("parcel")
	integer, _ := strconv.Atoi(parcel)
	encoded[integer] = data
	fmt.Printf("Recieved Parcel %s : %s\n", parcel, data)

}

func done(w http.ResponseWriter, req *http.Request) {
	var encjoin []string
	keys := make([]int, 0, len(encoded))
	for k := range encoded {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		fmt.Printf("Adding Encoded Chunk %d:\n%s\n", k, encoded[k])
		encjoin = append(encjoin, encoded[k])
	}

	fmt.Println("Base64 Encoded Output:")
	fmt.Println(strings.Join(encjoin, ""))
	fmt.Println(len(encjoin))
	uDec, _ := base64.RawURLEncoding.DecodeString(strings.Join(encjoin, ""))
	fmt.Printf("Decoded String \n%s\n", string(uDec))

	decrypted := decrypt(string(uDec), key)

	fmt.Println(decrypted)

}

var key string

func init() {
	bytes := make([]byte, 32) //generate a random 32 byte key for AES-256
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}

	key = hex.EncodeToString(bytes) //encode key in bytes to string and keep as secret, put in a vault
	fmt.Printf("key to encrypt/decrypt : %s\n", key)

}

func main() {

	http.HandleFunc("/delivery", collect)
	http.HandleFunc("/done", done)

	http.ListenAndServe("0.0.0.0:8443", nil)
}
