// Fuzzes fizz::client::deserializePsk: the client's serialized resumption
// state (PSK identity, secret, version/cipher/group, ALPN, ticket ages and
// times, server and client certificates), as an application loads it back
// from a PSK cache or disk. Deserialized PSKs are serialized again.
//
// Input: the serialized PSK bytes.
#include "fuzz_common.h"

#include <fizz/client/PskSerializationUtils.h>

using namespace fizz;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  try {
    client::CachedPsk psk;
    Error err;
    if (client::deserializePsk(
            psk, err, openssl::certificateSerializer(),
            folly::ByteRange(data, size)) == Status::Success) {
      std::string out;
      Error err2;
      (void)client::serializePsk(
          out, err2, openssl::certificateSerializer(), psk);
    }
  } catch (const std::exception&) {
  }
  return 0;
}
