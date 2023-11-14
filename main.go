package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	//var secret = "f62e5bcda4fae4f82370da0c6f20697b8f8447ef"
	//var auth = auth(secret)
	hostname := readfile("/etc/hostname")
	fmt.Printf("hello world\nfrom: %s\n", hostname)
}

func readfile(filepath string) (res []byte) {
	res, err := os.ReadFile(filepath)
	if err != nil {
		log.Fatal(err)
	}
	return res
}
