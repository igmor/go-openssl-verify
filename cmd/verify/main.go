package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/igmor/go-openssl-verify/pkg/verify"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <cert1.pem> [<cert2.pem> ...]\n", os.Args[0])
		os.Exit(1)
	}

	var certs []*x509.Certificate
	for _, filename := range os.Args[1:] {
		pemData, err := ioutil.ReadFile(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %s\n", filename, err)
			os.Exit(1)
		}

		cert, err := x509.ParseCertificate(pemData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %s\n", filename, err)
			os.Exit(1)
		}

		certs = append(certs, cert)
	}

	// Call Verify function with certs slice
	err := verify.Verify(certs[0], []*x509.Certificate{certs[1]}, []*x509.Certificate{certs[2]})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying certificates: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Certificates verified successfully")
}
