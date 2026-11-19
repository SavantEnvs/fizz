// Fuzzes fizz's Exported Authenticators (RFC 9261), both directions:
//  - ExportedAuthenticator::validate: the peer's authenticator request and
//    authenticator (CertificateRequest, Certificate, CertificateVerify and
//    Finished decoding, certificate parsing, signature and MAC checks);
//  - ExportedAuthenticator::makeAuthenticator: answering a peer's
//    authenticator request (request decoding, signature-scheme negotiation),
//    then validating our own answer;
//  - ExportedAuthenticator::getAuthenticatorContext.
// The handshake context and finished MAC key are fixed, as in upstream's test.
//
// Input: byte 0 picks the entry point; for validate a u16-length request
// followed by the authenticator.
#include "fuzz_common.h"

#include <fizz/extensions/exportedauth/ExportedAuthenticator.h>
#include <fizz/protocol/DefaultFactory.h>

using namespace fizz;

namespace {

const HasherFactoryWithMetadata* hasher(CipherSuite suite) {
  const HasherFactoryWithMetadata* ret = nullptr;
  HashFunction hash;
  Error err;
  FIZZ_THROW_ON_ERROR(getHashFunction(hash, err, suite), err);
  FIZZ_THROW_ON_ERROR(DefaultFactory().makeHasherFactory(ret, err, hash), err);
  return ret;
}

Buf fixed() {
  return folly::IOBuf::copyBuffer("12345678901234567890123456789012");
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static auto cert = fizz_fuzz::p256SelfCert();
  static const HasherFactoryWithMetadata* hashers[] = {
      hasher(CipherSuite::TLS_AES_128_GCM_SHA256),
      hasher(CipherSuite::TLS_AES_256_GCM_SHA384)};
  if (size < 1) {
    return 0;
  }
  fizz_fuzz::Reader r(data, size);
  uint8_t sel = r.u8();
  auto* h = hashers[(sel >> 2) & 1];
  auto ctx = (sel & 0x10) ? CertificateVerifyContext::Authenticator
                          : CertificateVerifyContext::Server;
  try {
    Error err;
    switch (sel % 3) {
      case 0: {
        auto request = r.chunk16();
        auto authenticator = r.rest();
        folly::Optional<std::vector<CertificateEntry>> certs;
        (void)ExportedAuthenticator::validate(
            certs, err, h, std::move(request), std::move(authenticator),
            fixed(), fixed(), ctx);
        break;
      }
      case 1: {
        Buf out;
        (void)ExportedAuthenticator::getAuthenticatorContext(
            out, err, r.rest());
        break;
      }
      case 2: {
        auto request = r.rest();
        Buf authenticator;
        if (ExportedAuthenticator::makeAuthenticator(
                authenticator, err, h,
                {SignatureScheme::ecdsa_secp256r1_sha256}, *cert,
                request->clone(), fixed(), fixed(), ctx) ==
                Status::Success &&
            authenticator) {
          folly::Optional<std::vector<CertificateEntry>> certs;
          Error err2;
          (void)ExportedAuthenticator::validate(
              certs, err2, h, std::move(request), std::move(authenticator),
              fixed(), fixed(), ctx);
        }
        break;
      }
    }
  } catch (const std::exception&) {
  }
  return 0;
}
