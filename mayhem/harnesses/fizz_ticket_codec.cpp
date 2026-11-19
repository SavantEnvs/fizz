// Fuzzes fizz's session-ticket state decoder, TicketCodec<Storage>::decode,
// for both certificate storage modes (X509: the client certificate is
// re-parsed from DER; IdentityOnly), as the server runs it on a decrypted
// ticket (resumption secret, version/cipher, times, ALPN, server cert
// identity, app token).
//
// Input: byte 0 = storage mode, then the encoded ticket state.
#include "fuzz_common.h"

#include <fizz/protocol/DefaultFactory.h>
#include <fizz/server/DefaultCertManager.h>
#include <fizz/server/TicketCodec.h>

using namespace fizz;
using namespace fizz::server;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static DefaultFactory factory;
  static auto certManager = [] {
    auto cm = std::make_shared<DefaultCertManager>();
    cm->addCertAndSetDefault(fizz_fuzz::p256SelfCert());
    return cm;
  }();
  if (size < 1) {
    return 0;
  }
  fizz_fuzz::Reader r(data, size);
  uint8_t mode = r.u8();
  try {
    if (mode & 1) {
      auto rs = TicketCodec<CertificateStorage::IdentityOnly>::decode(
          r.rest(), factory, *certManager);
      (void)TicketCodec<CertificateStorage::IdentityOnly>::encode(
          std::move(rs));
    } else {
      auto rs = TicketCodec<CertificateStorage::X509>::decode(
          r.rest(), factory, *certManager);
      (void)TicketCodec<CertificateStorage::X509>::encode(std::move(rs));
    }
  } catch (const std::exception&) {
  }
  return 0;
}
