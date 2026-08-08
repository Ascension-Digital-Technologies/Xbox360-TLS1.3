#include "xboxtls/xboxtls.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif
#include <stdio.h>
#include <string.h>
#include <vector>
using namespace xboxtls;
static int check(bool v, const char* n) {
    printf("[%s] %s\n", v ? "PASS" : "FAIL", n);
    return v ? 0 : 1;
}
static bool load(const char* p, std::vector<xt_u8>& o) {
    FILE* f = fopen(p, "rb");
    if (!f)
        return false;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) {
        fclose(f);
        return false;
    }
    o.resize((size_t)n);
    bool ok = fread(&o[0], 1, o.size(), f) == o.size();
    fclose(f);
    return ok;
}
static bool ecdsa_fixture(ByteSpan msg, std::vector<xt_u8>& pub, std::vector<xt_u8>& sig) {
    EVP_PKEY_CTX* kg = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, 0);
    EVP_PKEY* k = 0;
    bool ok = false;
    if (!kg || EVP_PKEY_keygen_init(kg) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kg, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(kg, &k) <= 0) {
        if (kg)
            EVP_PKEY_CTX_free(kg);
        return false;
    }
    EVP_PKEY_CTX_free(kg);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    pub.resize(65);
    size_t pn = 0;
    if (EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, &pub[0], pub.size(), &pn) <=
            0 ||
        pn != 65) {
        EVP_PKEY_free(k);
        return false;
    }
#else
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(k);
    if (!ec) {
        EVP_PKEY_free(k);
        return false;
    }
    const EC_GROUP* g = EC_KEY_get0_group(ec);
    const EC_POINT* q = EC_KEY_get0_public_key(ec);
    pub.resize(65);
    size_t pn = EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED, &pub[0], pub.size(), 0);
    EC_KEY_free(ec);
    if (pn != 65) {
        EVP_PKEY_free(k);
        return false;
    }
#endif
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    if (md && EVP_DigestSignInit(md, 0, EVP_sha256(), 0, k) == 1 &&
        EVP_DigestSignUpdate(md, msg.data, msg.size) == 1) {
        size_t n = 0;
        if (EVP_DigestSignFinal(md, 0, &n) == 1) {
            sig.resize(n);
            if (EVP_DigestSignFinal(md, &sig[0], &n) == 1) {
                sig.resize(n);
                ok = true;
            }
        }
    }
    if (md)
        EVP_MD_CTX_free(md);
    EVP_PKEY_free(k);
    return ok;
}

int main(int argc, char** argv) {
    int f = 0;
    if (argc != 6)
        return 2;
    std::vector<xt_u8> root, leaf;
    f += check(load(argv[1], root) && load(argv[2], leaf), "load native verifier fixtures");
    if (f)
        return 1;
    X509CertificateView lv;
    f += check(x509_parse_certificate(ByteSpan(&leaf[0], leaf.size()), &lv) == XT_OK,
               "parse native RSA leaf");
    NativeServerAuthVerifier v(0);
    f += check(v.add_trust_anchor(ByteSpan(&root[0], root.size())) == XT_OK,
               "native add trust anchor");
    CertificateChainView c;
    c.count = 1;
    c.entries[0].der = ByteSpan(&leaf[0], leaf.size());
    f += check(v.verify_chain(c, "example.com") == XT_OK, "native RSA chain signature + hostname");
    f += check(v.verify_chain(c, "wrong.example") == XT_ERR_VERIFY,
               "native hostname mismatch rejected");

    xt_u8 leaf_pin[32];
    sha256(ByteSpan(&leaf[0], leaf.size()), leaf_pin);
    f += check(v.set_leaf_certificate_sha256_pin(ByteSpan(leaf_pin, 32)) == XT_OK &&
                   v.verify_chain(c, "example.com") == XT_OK,
               "native leaf certificate pin accepted");
    leaf_pin[0] ^= 1;
    f += check(v.set_leaf_certificate_sha256_pin(ByteSpan(leaf_pin, 32)) == XT_OK &&
                   v.verify_chain(c, "example.com") == XT_ERR_VERIFY,
               "native leaf certificate pin mismatch rejected");
    v.clear_leaf_certificate_sha256_pin();
    xt_u8 msg[130];
    memset(msg, 0x5a, sizeof(msg));
    std::vector<xt_u8> sig;
    f += check(load(argv[3], sig), "load native RSA-PSS test signature");
    if (!sig.empty()) {
        f += check(v.verify_signature(SIG_RSA_PSS_RSAE_SHA256, lv, ByteSpan(msg, sizeof(msg)),
                                      ByteSpan(&sig[0], sig.size())) == XT_OK,
                   "native RSA-PSS verify");
        sig[7] ^= 1;
        f += check(v.verify_signature(SIG_RSA_PSS_RSAE_SHA256, lv, ByteSpan(msg, sizeof(msg)),
                                      ByteSpan(&sig[0], sig.size())) == XT_ERR_VERIFY,
                   "native RSA-PSS tamper rejection");
    }
    std::vector<xt_u8> pssroot, pssleaf;
    f += check(load(argv[4], pssroot) && load(argv[5], pssleaf),
               "load RSA-PSS certificate fixtures");
    if (!pssroot.empty() && !pssleaf.empty()) {
        NativeServerAuthVerifier pv(0);
        f += check(pv.add_trust_anchor(ByteSpan(&pssroot[0], pssroot.size())) == XT_OK,
                   "add RSA-PSS root");
        CertificateChainView pc;
        pc.count = 1;
        pc.entries[0].der = ByteSpan(&pssleaf[0], pssleaf.size());
        f += check(pv.verify_chain(pc, "pss.example.com") == XT_OK,
                   "native RSA-PSS certificate signature chain");
    }
    std::vector<xt_u8> epub, esig;
    f += check(ecdsa_fixture(ByteSpan(msg, sizeof(msg)), epub, esig),
               "generate P-256 ECDSA fixture");
    if (!epub.empty() && !esig.empty()) {
        X509CertificateView ev;
        ev.public_key_kind = PUBLIC_KEY_EC_P256;
        ev.subject_public_key_bits = ByteSpan(&epub[0], epub.size());
        f += check(v.verify_signature(SIG_ECDSA_SECP256R1_SHA256, ev, ByteSpan(msg, sizeof(msg)),
                                      ByteSpan(&esig[0], esig.size())) == XT_OK,
                   "native P-256 ECDSA verify");
        esig[esig.size() - 1] ^= 1;
        f += check(v.verify_signature(SIG_ECDSA_SECP256R1_SHA256, ev, ByteSpan(msg, sizeof(msg)),
                                      ByteSpan(&esig[0], esig.size())) == XT_ERR_VERIFY,
                   "native P-256 tamper rejection");
    }
    printf("\n%d failure(s)\n", f);
    return f ? 1 : 0;
}
