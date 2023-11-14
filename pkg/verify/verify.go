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

const BioBufferSize = 16 * 1024

// Verify verifies the certificate chain
func Verify(cert *x509.Certificate, roots []*x509.Certificate, intermediates []*x509.Certificate) (err error, bio_out []byte, bio_err []byte) {
	total_roots_len := make([]C.int, len(roots))
	var root_bytes []byte
	for i, root := range roots {
		total_roots_len[i] = C.int(len(root.Raw))
		root_bytes = append(root_bytes, root.Raw...)
	}

	total_intermediates_len := make([]C.int, len(intermediates))
	var intermediates_bytes []byte
	for i, intermediate := range intermediates {
		total_intermediates_len[i] = C.int(len(intermediate.Raw))
		intermediates_bytes = append(intermediates_bytes, intermediate.Raw...)
	}

	cert_raw := unsafe.Pointer(&cert.Raw[0])

	var roots_raw unsafe.Pointer
	var intermediates_raw unsafe.Pointer

	if len(root_bytes) > 0 {
		roots_raw = unsafe.Pointer(&root_bytes[0])
	}
	if len(intermediates_bytes) > 0 {
		intermediates_raw = unsafe.Pointer(&intermediates_bytes[0])
	}

	var input_roots_len *C.int
	if len(roots) > 0 {
		input_roots_len = &total_roots_len[0]
	}
	var input_intermediates_len *C.int
	if len(intermediates) > 0 {
		input_intermediates_len = &total_intermediates_len[0]
	}

	b_out := C.BIO_new(C.BIO_s_mem())
	b_err := C.BIO_new(C.BIO_s_mem())

	ret := C.verify(cert_raw, C.int(len(cert.Raw)), roots_raw, C.int(len(roots)), input_roots_len, intermediates_raw, C.int(len(intermediates)), input_intermediates_len, unsafe.Pointer(b_out), unsafe.Pointer(b_err))
	if ret <= 0 {
		err = fmt.Errorf("verify failed")
	}

	if b_out != nil {
		l := C.BIO_ctrl_pending(b_out)
		bio_out = make([]byte, l)
		if l > 0 {
			C.BIO_read(b_out, unsafe.Pointer(&bio_out[0]), C.int(l))
		}
		C.BIO_free(b_out)

	}

	if b_err != nil {
		l := C.BIO_ctrl_pending(b_err)
		bio_err = make([]byte, l)
		if l > 0 {
			C.BIO_read(b_err, unsafe.Pointer(&bio_err[0]), C.int(l))
		}
		C.BIO_free(b_err)
	}

	return err, bio_out, bio_err
}
