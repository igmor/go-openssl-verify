#ifndef __VERIFY_H__
#define __VERIFY_H__

int verify(void* cert_buff, int cert_len, // leaf certificate
           void* roots, int roots_len, int roots_lens[], // root certificates, trusted chain
           void* intermediates, int intermediates_len, int intermediates_lens[]); // intermediate certificates, untrusted chain

#endif //__VERIFY_H__
