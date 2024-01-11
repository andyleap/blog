//go:build ignore

package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	hash, err := bcrypt.GenerateFromPassword([]byte(os.Args[1]), 10)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(hash))
}
