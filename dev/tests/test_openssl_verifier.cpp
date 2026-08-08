#include "xboxtls/openssl_verifier.h"
#include "xboxtls/xboxtls.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <vector>

using namespace xboxtls;

static int check(bool v, const char* name) {
    printf("[%s] %s\n", v ? "PASS" : "FAIL", name);
    return v ? 0 : 1;
}

static bool load_file(const char* path, std::vector<xt_u8>& out) {
    FILE* f = fopen(path, "rb");
    if (!f)
        return false;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) {
        fclose(f);
        return false;
    }
    out.resize((size_t)n);
    bool ok = fread(&out[0], 1, (size_t)n, f) == (size_t)n;
    fclose(f);
    return ok;
}

int main(int argc, char** argv) {
    int fails = 0;
    if (argc != 4) {
        printf("usage: %s root.der leaf.der certverify-rsa-pss.sig\n", argv[0]);
        return 2;
    }
    std::vector<xt_u8> root, leaf;
    fails += check(load_file(argv[1], root) && load_file(argv[2], leaf), "load verifier fixtures");
    if (fails)
        return 1;

    X509CertificateView leaf_view;
    fails += check(x509_parse_certificate(ByteSpan(&leaf[0], leaf.size()), &leaf_view) == XT_OK,
                   "portable parser accepts OpenSSL leaf");

    OpenSslServerAuthVerifier verifier;
    fails += check(verifier.add_trust_anchor(ByteSpan(&root[0], root.size())) == XT_OK,
                   "add DER trust anchor");

    CertificateChainView chain;
    chain.count = 1;
    chain.entries[0].der = ByteSpan(&leaf[0], leaf.size());
    fails += check(verifier.verify_chain(chain, "example.com") == XT_OK,
                   "OpenSSL chain + hostname + serverAuth validation");
    fails += check(verifier.verify_chain(chain, "wrong.example") == XT_ERR_VERIFY,
                   "OpenSSL hostname mismatch rejected");

    xt_u8 transcript[32];
    memset(transcript, 0x42, sizeof(transcript));
    xt_u8 msg[160];
    size_t written = 0;
    fails +=
        check(build_server_certificate_verify_message(
                  ByteSpan(transcript, 32), MutableByteSpan(msg, sizeof(msg)), &written) == XT_OK &&
                  written == 130,
              "build CertificateVerify input");
    std::vector<xt_u8> sig;
    fails += check(load_file(argv[3], sig), "load RSA-PSS/SHA-256 fixture signature");
    if (!sig.empty()) {
        fails += check(verifier.verify_signature(SIG_RSA_PSS_RSAE_SHA256, leaf_view,
                                                 ByteSpan(msg, written),
                                                 ByteSpan(&sig[0], sig.size())) == XT_OK,
                       "RSA-PSS TLS 1.3 CertificateVerify validation");
        sig[0] ^= 1;
        fails += check(verifier.verify_signature(SIG_RSA_PSS_RSAE_SHA256, leaf_view,
                                                 ByteSpan(msg, written),
                                                 ByteSpan(&sig[0], sig.size())) == XT_ERR_VERIFY,
                       "RSA-PSS tamper rejection");
    }

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
