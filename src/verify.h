#ifndef __VERIFY_H__
#define __VERIFY_H__

static int verify(const char* cert_buff,
                  const char* roots,
                  int roots_lens[],
                  const char* intermediates,
                  int intermediates_lens[]);

#endif //__VERIFY_H__
