// Fuzzes fizz's experimental batch signatures: BatchSignaturePeerCert::verify
// on a peer's CertificateVerify signature for a batch scheme (BatchSignature
// wire decoding, Merkle path/index checks, root reconstruction, base
// signature verification) with the fixed P-256 test certificate as the
// verifier, as a client does when the server signs with a batch scheme.
//
// Input: byte 0 picks the batch scheme and context, a u16-length message,
// then the signature.
#include "fuzz_common.h"

#include <fizz/experimental/client/BatchSignaturePeerCert.h>

using namespace fizz;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static BatchSignaturePeerCert peer(fizz_fuzz::p256PeerCert());
  static const SignatureScheme kSchemes[] = {
      SignatureScheme::ecdsa_secp256r1_sha256_batch,
      SignatureScheme::rsa_pss_sha256_batch,
      SignatureScheme::ecdsa_secp256r1_sha256,
  };
  if (size < 1) {
    return 0;
  }
  fizz_fuzz::Reader r(data, size);
  uint8_t sel = r.u8();
  auto message = r.chunk16();
  auto signature = r.rest();
  try {
    Error err;
    (void)peer.verify(
        err, kSchemes[sel % 3],
        (sel & 4) ? CertificateVerifyContext::Client
                  : CertificateVerifyContext::Server,
        message->coalesce(), signature->coalesce());
  } catch (const std::exception&) {
  }
  return 0;
}
