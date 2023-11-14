package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/igmor/go-openssl-verify/pkg/verify"
	"github.com/spf13/cobra"
)

var trustedCerts *[]string
var untrustedCerts *[]string
var cert string

func init() {
	trustedCerts = rootCmd.PersistentFlags().StringArray("trusted", []string{}, "trusted certificates, aka root CAs")
	untrustedCerts = rootCmd.PersistentFlags().StringArray("untrusted", []string{}, "untrusted certificates, aka intermediates")
	rootCmd.PersistentFlags().StringVarP(&cert, "cert", "c", "", "filename of a leaf certificate to verify")
}

var rootCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify is openssl x509 verify wrapper",
	Run: func(cmd *cobra.Command, args []string) {
		if err := cmdVerify(cert, *trustedCerts, *untrustedCerts); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func cmdVerify(leafCert string, trustedCerts []string, untrustedCerts []string) error {
	if len(leafCert) == 0 {
		return fmt.Errorf("leaf certificate is required")
	}

	leafPemData, err := os.ReadFile(leafCert)
	if err != nil {
		return fmt.Errorf("error reading %s: %s", leafCert, err)
	}

	block, _ := pem.Decode(leafPemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("failed to decode PEM block containing public key")
	}

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing %s: %s", leafCert, err)
	}

	var trusted []*x509.Certificate
	for _, filename := range trustedCerts {
		pemData, err := os.ReadFile(filename)
		if err != nil {
			return err
		}

		block, _ := pem.Decode(pemData)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("failed to decode PEM block containing public key")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		trusted = append(trusted, cert)
	}

	var untrusted []*x509.Certificate
	for _, filename := range untrustedCerts {
		pemData, err := os.ReadFile(filename)
		if err != nil {
			return err
		}

		block, _ := pem.Decode(pemData)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("failed to decode PEM block containing public key")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		if err != nil {
			return err
		}

		untrusted = append(untrusted, cert)
	}
	// Call Verify function with certs slice
	err, bout, berr := verify.Verify(leaf, trusted, untrusted)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying certificates: %s\n", err)
		fmt.Fprintf(os.Stderr, string(berr))

		return err
	}

	fmt.Println("Certificates verified successfully")
	fmt.Println(string(bout))

	return nil
}
