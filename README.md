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

The library allows to bring a wider x509 support into GOLang ecosystem. 
