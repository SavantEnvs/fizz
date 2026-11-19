// Fuzzes fizz's stateless HelloRetryRequest cookies (server/AeadCookieCipher):
//  - getTokenOrRetry: a raw ClientHello record from the network (record and
//    ClientHello decoding, cookie extension lookup and decryption, or
//    building a stateless HRR from the hello);
//  - decrypt: a fuzz cookie, and a fuzz CookieState plaintext sealed with
//    the same token cipher and secret, so the CookieState decoder behind the
//    AEAD is reached.
//
// Input: byte 0 = mode, then the ClientHello record (mode 0), the cookie
// (mode 1) or the plaintext to seal (mode 2).
#include "fuzz_common.h"

#include <fizz/protocol/DefaultFactory.h>
#include <fizz/server/AeadCookieCipher.h>
#include <fizz/server/AeadTokenCipher.h>
#include <fizz/server/CookieTypes.h>
#include <fizz/server/FizzServerContext.h>

using namespace fizz;
using namespace fizz::server;

namespace {

const std::string kSecret(32, 'c');
const std::vector<std::string> kLabel{"Fizz Cookie Cipher v1"};

std::unique_ptr<Aead128GCMTokenCipher> tokenCipher() {
  auto tc = std::make_unique<Aead128GCMTokenCipher>(kLabel);
  std::vector<folly::ByteRange> secrets{folly::StringPiece(kSecret)};
  tc->setSecrets(secrets);
  return tc;
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static auto ctx = [] {
    auto c = std::make_shared<FizzServerContext>();
    c->setSupportedVersions({ProtocolVersion::tls_1_3});
    return c;
  }();
  static auto cipher = [] {
    auto c = std::make_shared<AES128CookieCipher>(tokenCipher());
    std::vector<folly::ByteRange> secrets{folly::StringPiece(kSecret)};
    c->setCookieSecrets(secrets);
    c->setContext(ctx.get());
    return c;
  }();
  static auto sealer = tokenCipher();
  if (size < 1) {
    return 0;
  }
  fizz_fuzz::Reader r(data, size);
  uint8_t mode = r.u8();
  try {
    switch (mode % 3) {
      case 0:
        (void)cipher->getTokenOrRetry(
            r.rest(), folly::IOBuf::copyBuffer("apptoken"));
        break;
      case 1:
        (void)cipher->decrypt(r.rest());
        break;
      case 2: {
        auto sealed = sealer->encrypt(r.rest());
        if (sealed) {
          (void)cipher->decrypt(std::move(*sealed));
        }
        break;
      }
    }
  } catch (const std::exception&) {
  }
  return 0;
}
