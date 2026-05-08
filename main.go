package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const addr = "localhost:9000"

func deriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

func encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

func decrypt(key []byte, cipherhex string) (string, error) {
	data, err := hex.DecodeString(cipherhex)
	if err != nil {
		return "", fmt.Errorf("invalid hex")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt failed")
	}

	return string(plaintext), nil
}

func receiveMessages(conn net.Conn, key []byte) {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		plaintext, err := decrypt(key, line)
		if err != nil {
			fmt.Printf("\n[decrypt error: %v]\n> ", err)
			continue
		}

		preview := line
		if len(preview) > 40 {
			preview = preview[:40] + "..."
		}

		ts := time.Now().Format("15:04:05")
		fmt.Printf("\n[%s] encrypted: %s\n[%s]      text: %s\n> ", ts, preview, ts, plaintext)
	}
}

func sendMessages(conn net.Conn, key []byte, scanner *bufio.Scanner) {
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		msg := strings.TrimSpace(scanner.Text())
		if msg == "" {
			continue
		}
		if msg == "/exit" {
			break
		}

		encrypted, err := encrypt(key, msg)
		if err != nil {
			fmt.Println("encrypt error:", err)
			continue
		}

		preview := encrypted
		if len(preview) > 40 {
			preview = preview[:40] + "..."
		}
		fmt.Println("sending:", preview)

		if _, err = fmt.Fprintln(conn, encrypted); err != nil {
			fmt.Println("connection lost")
			break
		}
	}
}

func runServer(key []byte, scanner *bufio.Scanner) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("listen error:", err)
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Printf("listening on %s\n", addr)

	conn, err := ln.Accept()
	if err != nil {
		fmt.Println("accept error:", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("client connected")

	go receiveMessages(conn, key)
	sendMessages(conn, key, scanner)
}

func runClient(key []byte, scanner *bufio.Scanner) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("connection failed, start server first")
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("connected")

	go receiveMessages(conn, key)
	sendMessages(conn, key, scanner)
}

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "server" && os.Args[1] != "client") {
		fmt.Println("usage: go run main.go [server|client]")
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Print("password: ")
	scanner.Scan()
	key := deriveKey(scanner.Text())

	fmt.Printf("key: %x\n\n", key)

	switch os.Args[1] {
	case "server":
		runServer(key, scanner)
	case "client":
		runClient(key, scanner)
	}
}
