#ifndef __VERIFY_H__
#define __VERIFY_H__

#include <openssl/bio.h>

int verify(void* cert_buff, int cert_len, // leaf certificate
           void* roots, int roots_len, int roots_lens[], // root certificates, trusted chain
           void* intermediates, int intermediates_len, int intermediates_lens[], // intermediate certificates, untrusted chain
           void* bio_out, void* bio_err); // output and error BIOs

#endif //__VERIFY_H__
