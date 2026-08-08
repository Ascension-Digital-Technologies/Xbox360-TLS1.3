#include "xboxtls/openssl_verifier.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

namespace xboxtls {

static X509* parse_cert(ByteSpan der) {
    if (!der.data || der.size == 0)
        return 0;
    const unsigned char* p = der.data;
    X509* x = d2i_X509(0, &p, (long)der.size);
    if (!x || p != der.data + der.size) {
        if (x)
            X509_free(x);
        return 0;
    }
    return x;
}

OpenSslServerAuthVerifier::OpenSslServerAuthVerifier() : store_(0) {
    store_ = X509_STORE_new();
}

OpenSslServerAuthVerifier::~OpenSslServerAuthVerifier() {
    if (store_)
        X509_STORE_free((X509_STORE*)store_);
    store_ = 0;
}

Error OpenSslServerAuthVerifier::use_default_trust_store() {
    if (!store_)
        return XT_ERR_VERIFY;
    return X509_STORE_set_default_paths((X509_STORE*)store_) == 1 ? XT_OK : XT_ERR_VERIFY;
}

Error OpenSslServerAuthVerifier::add_trust_anchor(ByteSpan der_certificate) {
    if (!store_)
        return XT_ERR_VERIFY;
    X509* cert = parse_cert(der_certificate);
    if (!cert)
        return XT_ERR_BAD_HANDSHAKE;
    int ok = X509_STORE_add_cert((X509_STORE*)store_, cert);
    X509_free(cert);
    // Duplicate anchors are harmless, but callers should not need OpenSSL
    // error-queue details to distinguish that case. Treat a failed add as
    // verification setup failure and remain fail-closed.
    return ok == 1 ? XT_OK : XT_ERR_VERIFY;
}

Error OpenSslServerAuthVerifier::verify_chain(const CertificateChainView& chain,
                                              const char* hostname) {
    if (!store_ || !hostname || !*hostname || chain.count == 0)
        return XT_ERR_VERIFY;

    X509* leaf = parse_cert(chain.entries[0].der);
    if (!leaf)
        return XT_ERR_BAD_HANDSHAKE;

    STACK_OF(X509)* untrusted = sk_X509_new_null();
    if (!untrusted) {
        X509_free(leaf);
        return XT_ERR_VERIFY;
    }

    bool parse_ok = true;
    for (size_t i = 1; i < chain.count; ++i) {
        X509* cert = parse_cert(chain.entries[i].der);
        if (!cert || sk_X509_push(untrusted, cert) == 0) {
            if (cert)
                X509_free(cert);
            parse_ok = false;
            break;
        }
    }

    X509_STORE_CTX* ctx = 0;
    int ok = 0;
    if (parse_ok) {
        ctx = X509_STORE_CTX_new();
        if (ctx && X509_STORE_CTX_init(ctx, (X509_STORE*)store_, leaf, untrusted) == 1) {
            X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx);
            if (param) {
                X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_SERVER);
                X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
                if (X509_VERIFY_PARAM_set1_host(param, hostname, 0) == 1)
                    ok = X509_verify_cert(ctx);
            }
        }
    }

    if (ctx)
        X509_STORE_CTX_free(ctx);
    while (sk_X509_num(untrusted) > 0) {
        X509* x = sk_X509_pop(untrusted);
        X509_free(x);
    }
    sk_X509_free(untrusted);
    X509_free(leaf);
    return ok == 1 ? XT_OK : XT_ERR_VERIFY;
}

Error OpenSslServerAuthVerifier::verify_signature(SignatureScheme scheme,
                                                  const X509CertificateView& leaf,
                                                  ByteSpan signed_message, ByteSpan signature) {
    if (!leaf.der.data || !signed_message.data || !signature.data)
        return XT_ERR_INVALID_ARGUMENT;

    X509* cert = parse_cert(leaf.der);
    if (!cert)
        return XT_ERR_BAD_HANDSHAKE;
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) {
        X509_free(cert);
        return XT_ERR_VERIFY;
    }

    const int base = EVP_PKEY_base_id(pkey);
    if ((scheme == SIG_ECDSA_SECP256R1_SHA256 && base != EVP_PKEY_EC) ||
        ((scheme == SIG_RSA_PSS_RSAE_SHA256 || scheme == SIG_RSA_PSS_PSS_SHA256) &&
         base != EVP_PKEY_RSA && base != EVP_PKEY_RSA_PSS)) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return XT_ERR_VERIFY;
    }

    EVP_MD_CTX* md = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pkctx = 0;
    int ok = 0;
    if (md && EVP_DigestVerifyInit(md, &pkctx, EVP_sha256(), 0, pkey) == 1) {
        bool configured = true;
        if (scheme == SIG_RSA_PSS_RSAE_SHA256 || scheme == SIG_RSA_PSS_PSS_SHA256) {
            configured = pkctx && EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) > 0 &&
                         EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, 32) > 0 &&
                         EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, EVP_sha256()) > 0;
        }
        if (configured && EVP_DigestVerifyUpdate(md, signed_message.data, signed_message.size) == 1)
            ok = EVP_DigestVerifyFinal(md, signature.data, signature.size);
    }

    if (md)
        EVP_MD_CTX_free(md);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return ok == 1 ? XT_OK : XT_ERR_VERIFY;
}

} // namespace xboxtls
