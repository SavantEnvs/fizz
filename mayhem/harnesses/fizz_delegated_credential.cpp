// Fuzzes fizz's delegated credentials (RFC 9345):
//  - DelegatedCredentialFactory::makePeerCertStatic: a peer's leaf
//    certificate entry carrying a delegated_credential extension, as a client
//    receives it in the server's Certificate message (extension decoding,
//    parent-certificate checks, credential time validity, signature
//    verification, credential public-key parsing);
//  - loadDCFromPEM: a combined credential + key PEM bundle.
//
// Input: byte 0 = mode; mode 0: the delegated_credential extension data,
// attached to the fixed P-256 test certificate; mode 1: the PEM text.
#include "fuzz_common.h"

#include <folly/ssl/OpenSSLCertUtils.h>

#include <fizz/extensions/delegatedcred/DelegatedCredentialFactory.h>
#include <fizz/extensions/delegatedcred/Serialization.h>

using namespace fizz;
using namespace fizz::extensions;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static auto certDer = [] {
    auto certs =
        folly::ssl::OpenSSLCertUtils::readCertsFromBuffer(test::kP256Certificate);
    return folly::ssl::OpenSSLCertUtils::derEncode(*certs[0]);
  }();
  if (size < 1) {
    return 0;
  }
  fizz_fuzz::Reader r(data, size);
  uint8_t mode = r.u8();
  try {
    Error err;
    if ((mode & 1) == 0) {
      CertificateEntry entry;
      entry.cert_data = certDer->clone();
      Extension ext;
      ext.extension_type = ExtensionType::delegated_credential;
      ext.extension_data = r.rest();
      entry.extensions.push_back(std::move(ext));
      std::unique_ptr<PeerCert> peer;
      (void)DelegatedCredentialFactory::makePeerCertStatic(
          peer, err, std::move(entry), true);
    } else {
      auto pem = r.rest();
      std::unique_ptr<SelfDelegatedCredential> cred;
      (void)loadDCFromPEM(
          cred, err, pem->moveToFbString().toStdString(),
          (mode & 2) ? DelegatedCredentialMode::Client
                     : DelegatedCredentialMode::Server);
    }
  } catch (const std::exception&) {
  }
  return 0;
}
