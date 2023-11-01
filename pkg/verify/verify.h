#ifndef __VERIFY_H__
#define __VERIFY_H__

int verify(void* cert_buff,
           int cert_len,
           void* roots,
           int roots_len,
           int roots_lens[],
           void* intermediates,
           int intermediates_len,
           int intermediates_lens[]);

#endif //__VERIFY_H__
