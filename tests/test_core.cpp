#include "xboxtls/xboxtls.h"
#include <stdio.h>
#include <string.h>

using namespace xboxtls;

static int hexval(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}
static bool eqhex(const xt_u8* p, size_t n, const char* s) {
    for (size_t i = 0; i < n; ++i) {
        int a = hexval(s[i * 2]), b = hexval(s[i * 2 + 1]);
        if (a < 0 || b < 0 || p[i] != (xt_u8)((a << 4) | b))
            return false;
    }
    return true;
}
static int check(bool v, const char* name) {
    printf("[%s] %s\n", v ? "PASS" : "FAIL", name);
    return v ? 0 : 1;
}

int main() {
    int fails = 0;
    const char* abc = "abc";
    xt_u8 h[32];
    sha256(ByteSpan((const xt_u8*)abc, 3), h);
    fails += check(eqhex(h, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                   "SHA-256 abc");

    xt_u8 key[20];
    memset(key, 0x0b, sizeof(key));
    const char* hi = "Hi There";
    xt_u8 hm[32];
    hmac_sha256(ByteSpan(key, 20), ByteSpan((const xt_u8*)hi, 8), hm);
    fails +=
        check(eqhex(hm, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
              "HMAC-SHA256 RFC4231");

    xt_u8 iv[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, nonce[12];
    make_record_nonce(iv, 1, nonce);
    xt_u8 exp[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10};
    fails += check(memcmp(nonce, exp, 12) == 0, "TLS record nonce XOR");

    xt_u8 rec[5] = {23, 0x03, 0x03, 0, 42};
    RecordHeader rh;
    fails += check(parse_record_header(ByteSpan(rec, 5), &rh) == XT_OK && rh.length == 42 &&
                       rh.type == 23,
                   "Record header parser");

    xt_u8 random[32];
    for (int i = 0; i < 32; ++i)
        random[i] = (xt_u8)i;
    xt_u8 sid[32];
    memset(sid, 0xaa, 32);
    xt_u8 ks[32];
    memset(ks, 0x55, 32);
    xt_u8 ch[1024];
    size_t n = 0;
    ClientHelloParams cp;
    cp.random32 = ByteSpan(random, 32);
    cp.session_id = ByteSpan(sid, 32);
    cp.key_share = ByteSpan(ks, 32);
    cp.group = GROUP_X25519;
    cp.server_name = "example.com";
    cp.alpn = "http/1.1";
    Error e = build_client_hello(cp, MutableByteSpan(ch, sizeof(ch)), &n);
    fails +=
        check(e == XT_OK && n > 100 && ch[0] == HS_CLIENT_HELLO, "TLS 1.3 ClientHello builder");

    xt_u8 gkey[16] = {0}, giv[12] = {0}, gpt[16] = {0}, gct[16], gtag[16];
    Error ge = aes128_gcm_encrypt(gkey, giv, ByteSpan(0, 0), ByteSpan(gpt, 16),
                                  MutableByteSpan(gct, 16), gtag);
    fails += check(ge == XT_OK && eqhex(gct, 16, "0388dace60b6a392f328c2b971b2fe78") &&
                       eqhex(gtag, 16, "ab6e47d42cec13bdf53a67b21257bddf"),
                   "AES-128-GCM NIST vector");
    xt_u8 gout[16];
    ge = aes128_gcm_decrypt(gkey, giv, ByteSpan(0, 0), ByteSpan(gct, 16), gtag,
                            MutableByteSpan(gout, 16));
    fails += check(ge == XT_OK && memcmp(gout, gpt, 16) == 0, "AES-128-GCM decrypt");

    xt_u8 traffic_secret[32];
    for (int i = 0; i < 32; ++i)
        traffic_secret[i] = (xt_u8)(0x80 + i);
    TrafficKeysAes128Gcm tx, rx;
    fails += check(derive_traffic_keys_sha256(ByteSpan(traffic_secret, 32), &tx) == XT_OK &&
                       derive_traffic_keys_sha256(ByteSpan(traffic_secret, 32), &rx) == XT_OK,
                   "TLS traffic key derivation");
    const char* msg = "encrypted tls13 record";
    xt_u8 wire[256], plain[256];
    size_t wire_n = 0, plain_n = 0;
    xt_u8 inner = 0;
    Error pe =
        protect_record_aes128_gcm(&tx, CONTENT_HANDSHAKE, ByteSpan((const xt_u8*)msg, strlen(msg)),
                                  3, MutableByteSpan(wire, sizeof(wire)), &wire_n);
    Error ue = unprotect_record_aes128_gcm(&rx, ByteSpan(wire, wire_n), &inner,
                                           MutableByteSpan(plain, sizeof(plain)), &plain_n);
    fails += check(pe == XT_OK && ue == XT_OK && inner == CONTENT_HANDSHAKE &&
                       plain_n == strlen(msg) && memcmp(plain, msg, plain_n) == 0 &&
                       tx.sequence_number == 1 && rx.sequence_number == 1,
                   "TLS 1.3 record protect/unprotect");
    TrafficKeysAes128Gcm badrx;
    derive_traffic_keys_sha256(ByteSpan(traffic_secret, 32), &badrx);
    wire[wire_n - 1] ^= 1;
    size_t bad_n = 0;
    xt_u8 bad_type = 0;
    fails += check(unprotect_record_aes128_gcm(&badrx, ByteSpan(wire, wire_n), &bad_type,
                                               MutableByteSpan(plain, sizeof(plain)),
                                               &bad_n) == XT_ERR_VERIFY &&
                       badrx.sequence_number == 0,
                   "TLS 1.3 rejects modified tag");

    const xt_u8 alice_priv[32] = {0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
                                  0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
                                  0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
    const xt_u8 bob_priv[32] = {0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f,
                                0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18,
                                0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb};
    xt_u8 alice_pub[32], bob_pub[32], shared1[32], shared2[32];
    x25519_public_from_private(alice_priv, alice_pub);
    x25519_public_from_private(bob_priv, bob_pub);
    fails += check(
        eqhex(alice_pub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a") &&
            eqhex(bob_pub, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
        "X25519 RFC7748 public keys");
    Error xs1 = x25519_shared_secret(alice_priv, bob_pub, shared1),
          xs2 = x25519_shared_secret(bob_priv, alice_pub, shared2);
    fails += check(
        xs1 == XT_OK && xs2 == XT_OK && memcmp(shared1, shared2, 32) == 0 &&
            eqhex(shared1, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
        "X25519 RFC7748 shared secret");

    xt_u8 sh[128];
    size_t sp = 0;
    sh[sp++] = HS_SERVER_HELLO;
    size_t lenpos = sp;
    sp += 3;
    sh[sp++] = 0x03;
    sh[sp++] = 0x03;
    for (int i = 0; i < 32; ++i)
        sh[sp++] = (xt_u8)(0x40 + i);
    sh[sp++] = 0;
    sh[sp++] = 0x13;
    sh[sp++] = 0x01;
    sh[sp++] = 0;
    size_t exlen = sp;
    sp += 2;
    sh[sp++] = 0;
    sh[sp++] = 0x2b;
    sh[sp++] = 0;
    sh[sp++] = 2;
    sh[sp++] = 0x03;
    sh[sp++] = 0x04;
    sh[sp++] = 0;
    sh[sp++] = 0x33;
    sh[sp++] = 0;
    sh[sp++] = 36;
    sh[sp++] = 0;
    sh[sp++] = 0x1d;
    sh[sp++] = 0;
    sh[sp++] = 32;
    memcpy(sh + sp, bob_pub, 32);
    sp += 32;
    size_t extn = sp - (exlen + 2);
    sh[exlen] = (xt_u8)(extn >> 8);
    sh[exlen + 1] = (xt_u8)extn;
    size_t bodylen = sp - 4;
    sh[lenpos] = (xt_u8)(bodylen >> 16);
    sh[lenpos + 1] = (xt_u8)(bodylen >> 8);
    sh[lenpos + 2] = (xt_u8)bodylen;
    ServerHelloInfo shi;
    Error she = parse_server_hello(ByteSpan(sh, sp), &shi);
    fails += check(she == XT_OK && shi.selected_version == 0x0304 &&
                       shi.cipher_suite == TLS_AES_128_GCM_SHA256 && shi.group == GROUP_X25519 &&
                       shi.key_share_length == 32 && memcmp(shi.key_share, bob_pub, 32) == 0,
                   "TLS 1.3 ServerHello parser");

    // P-256 key generation/key agreement and HelloRetryRequest selected-group/cookie handling.
    xt_u8 p1[32] = {0}, p2[32] = {0}, p1pub[65], p2pub[65], p1s[32], p2s[32];
    p1[31] = 1;
    p2[31] = 2;
    Error p1e = p256_public_from_private(p1, p1pub), p2e = p256_public_from_private(p2, p2pub);
    Error ps1 = p256_shared_secret(p1, p2pub, p1s), ps2 = p256_shared_secret(p2, p1pub, p2s);
    fails += check(p1e == XT_OK && p2e == XT_OK && p1pub[0] == 4 &&
                       eqhex(p1pub + 1, 32,
                             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296") &&
                       eqhex(p1pub + 33, 32,
                             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5") &&
                       ps1 == XT_OK && ps2 == XT_OK && memcmp(p1s, p2s, 32) == 0,
                   "P-256 public key + ECDH");

    static const xt_u8 hrr_random[32] = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
                                         0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                         0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
                                         0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    xt_u8 hrr[160];
    size_t hp = 0;
    hrr[hp++] = HS_SERVER_HELLO;
    size_t hl = hp;
    hp += 3;
    hrr[hp++] = 3;
    hrr[hp++] = 3;
    memcpy(hrr + hp, hrr_random, 32);
    hp += 32;
    hrr[hp++] = 0;
    hrr[hp++] = 0x13;
    hrr[hp++] = 0x01;
    hrr[hp++] = 0;
    size_t he = hp;
    hp += 2;
    hrr[hp++] = 0;
    hrr[hp++] = 0x2b;
    hrr[hp++] = 0;
    hrr[hp++] = 2;
    hrr[hp++] = 3;
    hrr[hp++] = 4;
    hrr[hp++] = 0;
    hrr[hp++] = 0x33;
    hrr[hp++] = 0;
    hrr[hp++] = 2;
    hrr[hp++] = 0;
    hrr[hp++] = 0x17;
    hrr[hp++] = 0;
    hrr[hp++] = 0x2c;
    hrr[hp++] = 0;
    hrr[hp++] = 5;
    hrr[hp++] = 0;
    hrr[hp++] = 3;
    hrr[hp++] = 1;
    hrr[hp++] = 2;
    hrr[hp++] = 3;
    size_t hen = hp - (he + 2);
    hrr[he] = (xt_u8)(hen >> 8);
    hrr[he + 1] = (xt_u8)hen;
    size_t hbody = hp - 4;
    hrr[hl] = (xt_u8)(hbody >> 16);
    hrr[hl + 1] = (xt_u8)(hbody >> 8);
    hrr[hl + 2] = (xt_u8)hbody;
    ServerHelloInfo hrri;
    Error hrre = parse_server_hello(ByteSpan(hrr, hp), &hrri);
    ClientHelloParams cp2;
    cp2.random32 = ByteSpan(random, 32);
    cp2.session_id = ByteSpan(sid, 32);
    cp2.key_share = ByteSpan(p1pub, 65);
    cp2.group = GROUP_SECP256R1;
    cp2.server_name = "example.com";
    cp2.cookie = ByteSpan(hrri.cookie, hrri.cookie_length);
    xt_u8 ch2[1200];
    size_t ch2n = 0;
    Error ch2e = build_client_hello(cp2, MutableByteSpan(ch2, sizeof(ch2)), &ch2n);
    fails += check(hrre == XT_OK && hrri.hello_retry_request && hrri.group == GROUP_SECP256R1 &&
                       hrri.cookie_length == 3 && ch2e == XT_OK && ch2n > 150,
                   "TLS 1.3 HelloRetryRequest + P-256 ClientHello2");

    // TLS 1.3 handshake message deframing across arbitrary record boundaries.
    xt_u8 ee_msg[] = {HS_ENCRYPTED_EXTENSIONS, 0, 0, 11, 0, 9, 0, 0x10, 0, 5, 0, 3, 2, 'h', '2'};
    xt_u8 frame_storage[128];
    HandshakeDeframer deframer(MutableByteSpan(frame_storage, sizeof(frame_storage)));
    Error de1 = deframer.append(ByteSpan(ee_msg, 6));
    HandshakeMessage fm;
    Error dp1 = deframer.peek(&fm);
    Error de2 = deframer.append(ByteSpan(ee_msg + 6, sizeof(ee_msg) - 6));
    Error dp2 = deframer.peek(&fm);
    EncryptedExtensionsInfo eei;
    Error eep = (dp2 == XT_OK) ? parse_encrypted_extensions(fm, &eei) : dp2;
    fails += check(de1 == XT_OK && dp1 == XT_ERR_BUFFER_TOO_SMALL && de2 == XT_OK && dp2 == XT_OK &&
                       fm.type == HS_ENCRYPTED_EXTENSIONS && eep == XT_OK && eei.has_alpn &&
                       eei.alpn.size == 2 && memcmp(eei.alpn.data, "h2", 2) == 0,
                   "TLS handshake deframer + EncryptedExtensions ALPN");
    fails += check(deframer.consume() == XT_OK && deframer.buffered() == 0,
                   "TLS handshake deframer consume");

    // Minimal Certificate and CertificateVerify framing/parser tests. Certificate bytes are
    // intentionally synthetic; X.509 validation and CertificateVerify signature verification are
    // separate milestones.
    xt_u8 cert_msg[] = {HS_CERTIFICATE, 0, 0, 12, 0, 0, 0, 8, 0, 0, 3, 0x30, 0x01, 0x00, 0, 0};
    HandshakeMessage cm;
    size_t cmn = 0;
    CertificateInfo ci;
    ByteSpan leaf, leafext;
    Error cme = parse_handshake_message(ByteSpan(cert_msg, sizeof(cert_msg)), &cm, &cmn);
    Error cie = (cme == XT_OK) ? parse_certificate(cm, &ci) : cme;
    Error cle = (cie == XT_OK) ? first_certificate_der(ci, &leaf, &leafext) : cie;
    fails += check(cle == XT_OK && leaf.size == 3 && leaf.data[0] == 0x30 && leafext.size == 0,
                   "TLS Certificate parser exposes leaf DER");
    xt_u8 cv_msg[] = {HS_CERTIFICATE_VERIFY, 0, 0, 8, 0x08, 0x04, 0, 4, 1, 2, 3, 4};
    HandshakeMessage cvm;
    size_t cvn = 0;
    CertificateVerifyInfo cvi;
    Error cve = parse_handshake_message(ByteSpan(cv_msg, sizeof(cv_msg)), &cvm, &cvn);
    if (cve == XT_OK)
        cve = parse_certificate_verify(cvm, &cvi);
    fails += check(cve == XT_OK && cvi.algorithm == 0x0804 && cvi.signature.size == 4,
                   "TLS CertificateVerify parser");

    // Finished generation/verification and application-secret transition.
    KeyScheduleSha256 sched;
    xt_u8 no_psk[32];
    memset(no_psk, 0, 32);
    Error ke = sched.derive_early_secret(ByteSpan(no_psk, 0));
    xt_u8 transcript_before_sh[32];
    sha256(ByteSpan(ch, n), transcript_before_sh); // deterministic fixture transcript
    if (ke == XT_OK)
        ke = sched.derive_handshake_secret(ByteSpan(shared1, 32),
                                           ByteSpan(transcript_before_sh, 32));
    TranscriptHash flight_transcript;
    flight_transcript.update(ByteSpan(ch, n));
    flight_transcript.update(ByteSpan(sh, sp));
    flight_transcript.update(ByteSpan(ee_msg, sizeof(ee_msg)));
    flight_transcript.update(ByteSpan(cert_msg, sizeof(cert_msg)));
    flight_transcript.update(ByteSpan(cv_msg, sizeof(cv_msg)));
    xt_u8 before_finished_hash[32];
    flight_transcript.snapshot(before_finished_hash);
    xt_u8 sf[36];
    size_t sfn = 0;
    Error sfe = build_finished_sha256(ByteSpan(sched.server_handshake_traffic_secret, 32),
                                      ByteSpan(before_finished_hash, 32),
                                      MutableByteSpan(sf, sizeof(sf)), &sfn);
    HandshakeMessage sfm;
    size_t sfmc = 0;
    Error sfpe = parse_handshake_message(ByteSpan(sf, sfn), &sfm, &sfmc);
    Error sfve = (sfpe == XT_OK)
                     ? verify_finished_sha256(ByteSpan(sched.server_handshake_traffic_secret, 32),
                                              ByteSpan(before_finished_hash, 32), sfm)
                     : sfpe;
    fails += check(ke == XT_OK && sfe == XT_OK && sfve == XT_OK && sfn == 36,
                   "TLS 1.3 server Finished verify_data");
    sf[10] ^= 1;
    HandshakeMessage badfm;
    size_t badfc = 0;
    parse_handshake_message(ByteSpan(sf, sfn), &badfm, &badfc);
    fails +=
        check(verify_finished_sha256(ByteSpan(sched.server_handshake_traffic_secret, 32),
                                     ByteSpan(before_finished_hash, 32), badfm) == XT_ERR_VERIFY,
              "TLS 1.3 Finished rejects tampering");
    sf[10] ^= 1;
    flight_transcript.update(ByteSpan(sf, sfn));
    xt_u8 through_server_finished[32];
    flight_transcript.snapshot(through_server_finished);
    Error me = sched.derive_master_secret(ByteSpan(through_server_finished, 32));
    xt_u8 cf[36];
    size_t cfn = 0;
    Error cfe = build_finished_sha256(ByteSpan(sched.client_handshake_traffic_secret, 32),
                                      ByteSpan(through_server_finished, 32),
                                      MutableByteSpan(cf, sizeof(cf)), &cfn);
    TrafficKeysAes128Gcm capp, sapp;
    Error cka =
        derive_traffic_keys_sha256(ByteSpan(sched.client_application_traffic_secret, 32), &capp);
    Error ska =
        derive_traffic_keys_sha256(ByteSpan(sched.server_application_traffic_secret, 32), &sapp);
    fails += check(me == XT_OK && cfe == XT_OK && cfn == 36 && cka == XT_OK && ska == XT_OK &&
                       memcmp(capp.key, sapp.key, 16) != 0,
                   "TLS 1.3 client Finished + application traffic keys");

    xt_u8 upd_secret[32];
    for (int i = 0; i < 32; ++i)
        upd_secret[i] = (xt_u8)i;
    TrafficKeysAes128Gcm upd_keys;
    Error upe = derive_traffic_keys_sha256(ByteSpan(upd_secret, 32), &upd_keys);
    xt_u8 old_key[16];
    memcpy(old_key, upd_keys.key, 16);
    if (upe == XT_OK)
        upe = update_traffic_secret_sha256(upd_secret, &upd_keys);
    fails += check(upe == XT_OK && memcmp(old_key, upd_keys.key, 16) != 0 &&
                       upd_keys.sequence_number == 0,
                   "TLS 1.3 traffic secret KeyUpdate");

    printf("\n%d failure(s)\n", fails);
    return fails ? 1 : 0;
}
