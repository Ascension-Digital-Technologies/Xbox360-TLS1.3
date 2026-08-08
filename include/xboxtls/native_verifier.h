#ifndef XBOXTLS_NATIVE_VERIFIER_H
#define XBOXTLS_NATIVE_VERIFIER_H

#include "authentication.h"
#include "platform.h"

namespace xboxtls {

class NativeServerAuthVerifier : public ServerAuthVerifier {
  public:
    explicit NativeServerAuthVerifier(Platform* platform);
    Error add_trust_anchor(ByteSpan der_certificate);
    Error clear_trust_anchors();
    Error load_trust_store(ByteSpan compact_store, size_t* loaded_count);

    virtual Error verify_chain(const CertificateChainView& chain, const char* hostname);
    virtual Error verify_signature(SignatureScheme scheme, const X509CertificateView& leaf,
                                   ByteSpan signed_message, ByteSpan signature);

  private:
    Platform* platform_;
    ByteSpan anchors_[16];
    size_t anchor_count_;
};

Error native_rsa_pss_sha256_verify(ByteSpan rsa_public_key_der, ByteSpan message,
                                   ByteSpan signature);
Error native_rsa_pkcs1_sha256_verify(ByteSpan rsa_public_key_der, ByteSpan message,
                                     ByteSpan signature);
Error native_p256_ecdsa_sha256_verify(ByteSpan uncompressed_public_key, ByteSpan message,
                                      ByteSpan signature);

} // namespace xboxtls

#endif
