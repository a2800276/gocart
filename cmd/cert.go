package main

import "fmt"
import "github.com/a2800276/gocart/x509"

func main() {
	fmt.Println("hi")
	x509.FastParsePKCS1PrivateKey(nil)
}
