#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include "verify.h"

typedef struct _BIOContext {
    BIO *bio_out;
    BIO *bio_err;
} BIOContext;

static int v_verbose = 0, vflags = 0;

static X509* load_cert(void* cert_buff, int cert_len)
{
        BIO *bio_mem = BIO_new(BIO_s_mem());
        BIO_write(bio_mem, cert_buff, cert_len);
        X509* cert = d2i_X509_bio(bio_mem, NULL);
        BIO_free(bio_mem);

        return cert;
}

static void nodes_print(BIOContext *bio_ctx, const char *name, STACK_OF(X509_POLICY_NODE) *nodes)
{
    X509_POLICY_NODE *node;
    int i;

    BIO_printf(bio_ctx->bio_err, "%s Policies:", name);
    if (nodes) {
        BIO_puts(bio_ctx->bio_err, "\n");
        for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++) {
            node = sk_X509_POLICY_NODE_value(nodes, i);
            X509_POLICY_NODE_print(bio_ctx->bio_err, node, 2);
        }
    } else {
        BIO_puts(bio_ctx->bio_err, " <empty>\n");
    }
}

void policies_print(X509_STORE_CTX *ctx, BIOContext* bio_ctx)
{
    X509_POLICY_TREE *tree;
    int explicit_policy;

    tree = X509_STORE_CTX_get0_policy_tree(ctx);
    explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

    BIO_printf(bio_ctx->bio_err, "Require explicit Policy: %s\n",
               explicit_policy ? "True" : "False");

    nodes_print(bio_ctx, "Authority", X509_policy_tree_get0_policies(tree));
    nodes_print(bio_ctx, "User", X509_policy_tree_get0_user_policies(tree));
}

int check(X509_STORE *ctx, BIOContext* bio_ctx, void *cert, int cert_len,
          STACK_OF(X509) *uchain, STACK_OF(X509) *tchain, int show_chain);

static int cb(int ok, X509_STORE_CTX *ctx, BIOContext* bio_ctx);

int verify(void* cert_buff, int cert_len,
           void* roots, int roots_len, int roots_lens[], 
           void* intermediates, int intermediates_len, int intermediates_lens[], void* bio_out, void* bio_err)
{
    X509_STORE *ctx = NULL;
    STACK_OF(X509) *uchain = NULL, *tchain = NULL;
    int ret = 0;

    ctx = X509_STORE_new();
    if (ctx == NULL)
        goto end;

    BIOContext bio_ctx;
    bio_ctx.bio_out = bio_out;
    bio_ctx.bio_err = bio_err;

    if (cert_buff != NULL) {
        uchain = sk_X509_new_null();
        if (uchain == NULL) {
            BIO_printf(bio_ctx.bio_err, "memory allocation failure\n");
            goto end;
        }
        tchain = sk_X509_new_null();
        if (tchain == NULL) {
            BIO_printf(bio_ctx.bio_err, "memory allocation failure\n");
            goto end;
        }
    }

    // trust root certs
    for (int i = 0, root_offset = 0; i < roots_len; root_offset += roots_lens[i], i++) {
        if (!sk_X509_push(tchain, load_cert(roots + root_offset, roots_lens[i]))) {
            BIO_printf(bio_ctx.bio_err, "memory allocation failure\n");
            goto end;
        }
    }

    // don't trust intermediate certs
    for (int i = 0, intermediate_offset = 0; i < intermediates_len; intermediate_offset += intermediates_lens[i], i++) {
        if (!sk_X509_push(uchain, load_cert(intermediates + intermediate_offset, intermediates_lens[i]))) {
            BIO_printf(bio_ctx.bio_err, "memory allocation failure\n");
            goto end;
        }
    }

    ret = check(ctx, &bio_ctx, cert_buff, cert_len, uchain, tchain, 1);

 end:
    if (ctx != NULL)
        X509_STORE_free(ctx);
    if (uchain != NULL)
        sk_X509_pop_free(uchain, X509_free);
    if (tchain != NULL)
        sk_X509_pop_free(tchain, X509_free);

    return ret;
}

int check(X509_STORE *ctx, BIOContext *bio_ctx, void *cert, int cert_len,
          STACK_OF(X509) *uchain, STACK_OF(X509) *tchain, int show_chain)
{
    X509 *x = NULL;
    int i = 0, ret = 0;
    X509_STORE_CTX *csc;
    STACK_OF(X509) *chain = NULL;
    int num_untrusted;

    x = load_cert(cert, cert_len);
    if (x == NULL)
        goto end;

    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
        BIO_printf(bio_ctx->bio_err, "error %s: X.509 store context allocation failed\n");
        goto end;
    }

    X509_STORE_set_flags(ctx, vflags);
    if (!X509_STORE_CTX_init(csc, ctx, x, uchain)) {
        X509_STORE_CTX_free(csc);
        BIO_printf(bio_ctx->bio_err,
                   "error %s: X.509 store context initialization failed\n");
        goto end;
    }
    if (tchain != NULL)
        X509_STORE_CTX_set0_trusted_stack(csc, tchain);
    i = X509_verify_cert(csc);
    if (i > 0 && X509_STORE_CTX_get_error(csc) == X509_V_OK) {
        BIO_printf(bio_ctx->bio_out, " OK\n");
        ret = 1;
        if (show_chain) {
            int j;

            chain = X509_STORE_CTX_get1_chain(csc);
            num_untrusted = X509_STORE_CTX_get_num_untrusted(csc);
            BIO_printf(bio_ctx->bio_out, "Chain:\n");
            for (j = 0; j < sk_X509_num(chain); j++) {
                X509 *cert = sk_X509_value(chain, j);
                BIO_printf(bio_ctx->bio_out, "depth=%d: ", j);
                X509_NAME_print_ex_fp(stdout,
                                      X509_get_subject_name(cert),
                                      0, XN_FLAG_SEP_COMMA_PLUS | XN_FLAG_SEP_MULTILINE);
                if (j < num_untrusted)
                    BIO_printf(bio_ctx->bio_out, " (untrusted)");
                BIO_printf(bio_ctx->bio_out, "\n");
            }
            sk_X509_pop_free(chain, X509_free);
        }
    } else {
        BIO_printf(bio_ctx->bio_err,
                   "error : verification failed\n");
        cb(i, csc, bio_ctx);
    }
    X509_STORE_CTX_free(csc);

 end:
    if (i <= 0)
        ERR_print_errors(bio_ctx->bio_err);
    X509_free(x);

    return ret;
}

static int cb(int ok, X509_STORE_CTX *ctx, BIOContext* bio_ctx)
{
    int cert_error = X509_STORE_CTX_get_error(ctx);
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);

    if (!ok) {
        if (current_cert != NULL) {
            X509_NAME_print_ex(bio_ctx->bio_err,
                            X509_get_subject_name(current_cert),
                            0, XN_FLAG_SEP_COMMA_PLUS | XN_FLAG_SEP_MULTILINE);
            BIO_printf(bio_ctx->bio_err, "\n");
        }
        BIO_printf(bio_ctx->bio_err, "%serror %d at %d depth lookup: %s\n",
               X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path] " : "",
               cert_error,
               X509_STORE_CTX_get_error_depth(ctx),
               X509_verify_cert_error_string(cert_error));

        /*
         * Pretend that some errors are ok, so they don't stop further
         * processing of the certificate chain.  Setting ok = 1 does this.
         * After X509_verify_cert() is done, we verify that there were
         * no actual errors, even if the returned value was positive.
         */
        switch (cert_error) {
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            policies_print(ctx, bio_ctx);
            /* fall through */
        case X509_V_ERR_CERT_HAS_EXPIRED:
            /* Continue even if the leaf is a self-signed cert */
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            /* Continue after extension errors too */
        case X509_V_ERR_INVALID_CA:
        case X509_V_ERR_INVALID_NON_CA:
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        case X509_V_ERR_CRL_HAS_EXPIRED:
        case X509_V_ERR_CRL_NOT_YET_VALID:
        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
            /* errors due to strict conformance checking (-x509_strict) */
        case X509_V_ERR_INVALID_PURPOSE:
        case X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA:
        case X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN:
        case X509_V_ERR_CA_BCONS_NOT_CRITICAL:
        case X509_V_ERR_CA_CERT_MISSING_KEY_USAGE:
        case X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA:
        case X509_V_ERR_ISSUER_NAME_EMPTY:
        case X509_V_ERR_SUBJECT_NAME_EMPTY:
        case X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL:
        case X509_V_ERR_EMPTY_SUBJECT_ALT_NAME:
        case X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY:
        case X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL:
        case X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL:
        case X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER:
        case X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER:
        case X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3:
            ok = 1;
        }
        return ok;

    }
    if (cert_error == X509_V_OK && ok == 2)
        policies_print(ctx, bio_ctx);
    return ok;
}