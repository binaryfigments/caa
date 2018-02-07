package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/binaryfigments/caa"
)

func main() {
	hostname := strings.ToLower(os.Args[1])
	nameserver := strings.ToLower(os.Args[2])

	caadata := pkicaa.Get(hostname, nameserver)

	json, err := json.MarshalIndent(caadata, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", json)
}
