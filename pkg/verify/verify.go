package verify

// #cgo CFLAGS: -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lssl -lcrypto
// #include "verify.h"
import "C"

import (
	"crypto/x509"

	"fmt"
	"unsafe"
)

// Verify verifies the certificate chain
func Verify(cert *x509.Certificate, roots []*x509.Certificate, intermediates []*x509.Certificate) (err error) {
	total_roots_len := make([]C.int, 0, len(roots))
	var root_bytes []byte
	for i, root := range roots {
		total_roots_len[i] = C.int(len(root.Raw))
		root_bytes = append(root_bytes, root.Raw...)
	}

	total_intermediates_len := make([]C.int, 0, len(intermediates))
	var intermediates_bytes []byte
	for i, intermediate := range intermediates {
		total_intermediates_len[i] = C.int(len(intermediate.Raw))
		intermediates_bytes = append(intermediates_bytes, intermediate.Raw...)
	}

	cert_raw := unsafe.Pointer(&cert.Raw[0])
	roots_raw := unsafe.Pointer(&root_bytes[0])
	intermediates_raw := unsafe.Pointer(&intermediates_bytes[0])

	ret := C.verify(cert_raw, C.int(len(cert.Raw)), roots_raw, C.int(len(roots)), &total_roots_len[0], intermediates_raw, C.int(len(intermediates)), &total_intermediates_len[0])
	if ret != 0 {
		err = fmt.Errorf("verify failed")
	}
	return nil
}
