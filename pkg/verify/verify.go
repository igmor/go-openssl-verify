package verify

// CPPFLAGS: -I/usr/local/include -I ../src
// LDFLAGS: -L/usr/local/lib -lssl -lcrypto
// #include <stdlib.h>
// #include <verify.h>
import "C"

import (
	"crypto/x509"

	"fmt"
	"unsafe"
)

func Verify(cert *x509.Certificate, roots []*x509.Certificate, intermediates []*x509.Certificate) (err error) {
	total_roots_len := make([]int, 0, len(roots))
	var root_bytes []byte
	for i, root := range roots {
		total_roots_len[i] = len(root.Raw)
		root_bytes = append(root_bytes, root.Raw...)
	}

	total_intermediates_len := make([]int, 0, len(intermediates))
	var intermediates_bytes []byte
	for i, intermediate := range intermediates {
		total_intermediates_len[i] = len(intermediate.Raw)
		intermediates_bytes = append(intermediates_bytes, intermediate.Raw...)
	}

	cert_raw := unsafe.Pointer(&cert.Raw[0])
	roots_raw := unsafe.Pointer(&root_bytes[0])
	intermediates_raw := unsafe.Pointer(&intermediates_bytes[0])

	ret := C.verify(cert_raw, len(cert.Raw), roots_raw, total_roots_len, len(roots), intermediates_raw, total_intermediates_len, len(intermediates))
	if ret != 0 {
		err = fmt.Errorf("verify failed")
	}
	return nil
}
