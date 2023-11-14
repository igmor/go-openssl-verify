# go-openssl-verify

The "go-openssl-verify" library leverages the capabilities of Golang's x509 certificates while optimizing the certificate verification process by delegating the verification chain to the OpenSSL facility. This approach enhances the security and performance of certificate validation, offering a robust solution compared to the native Golang "crypto/x509" verification function.
Golang x509 supports a subset of x509 standard, ie:

```
// The package targets the X.509 technical profile defined by the IETF (RFC
// 2459/3280/5280), and as further restricted by the CA/Browser Forum Baseline
// Requirements. There is minimal support for features outside of these
// profiles, as the primary goal of the package is to provide compatibility
// with the publicly trusted TLS certificate ecosystem and its policies and
// constraints.
```

The library allows us to bring a wider x509 support into the Go ecosystem. 

To verify certificates one would need to call this function

```
err, out_stream, err_stream := Verify(cert, []*x509.Certificate{rootCert}, []*x509.Certificate{IntermediateCert})
```

err, out_stream and err_stream will be an error, output, and error buffers from openssl x509 verify function.

# Openssl

The library relies on openssl headers and libraries at the following locations:

CFLAGS: `-I/usr/local/include`
LDFLAGS: `-L/usr/local/lib -lssl -lcrypt`

The current version was built and tested with Openssl 3.1.4

# Using a command line

```
./go-openssl-verify verify --cert scripts/leaf.pem --untrusted scripts/intermediate.pem --trusted scripts/root.pem 
```

Output when the chain is trusted:

```
Certificates verified successfully
 OK
Chain:
depth=0:  (untrusted)
depth=1:  (untrusted)
depth=2: 
```

Enjoy!
