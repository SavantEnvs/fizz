// Fuzzes fizz's token binding (RFC 8471) server-side validation: decode a
// TokenBindingMessage as an HTTP client sends it, then run
// Validator::validateTokenBinding on each binding against a fixed exported
// keying material (binding key parsing, EC point and ECDSA signature
// reconstruction, signature verification).
//
// Input: the TokenBindingMessage bytes.
#include "fuzz_common.h"

#include <fizz/extensions/tokenbinding/Types.h>
#include <fizz/extensions/tokenbinding/Validator.h>

using namespace fizz;
using namespace fizz::extensions;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static const Buf ekm = folly::IOBuf::copyBuffer(std::string(32, 'e'));
  auto buf = folly::IOBuf::copyBuffer(data, size);
  try {
    TokenBindingMessage msg;
    Error err;
    folly::io::Cursor cursor(buf.get());
    if (decode(msg, err, cursor) != Status::Success) {
      return 0;
    }
    for (auto& binding : msg.tokenbindings) {
      (void)Validator::validateTokenBinding(
          std::move(binding), ekm,
          std::vector<TokenBindingKeyParameters>{
              TokenBindingKeyParameters::ecdsap256,
              TokenBindingKeyParameters::ed25519_experimental});
    }
  } catch (const std::exception&) {
  }
  return 0;
}
