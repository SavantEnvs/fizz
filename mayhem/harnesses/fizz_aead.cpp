// Fuzzes fizz's AEAD implementations through the Aead interface the record
// layer uses: OpenSSL EVP AES-GCM / ChaCha20-Poly1305 and the libaegis
// AEGIS-128L / AEGIS-256 / AEGIS-128X2 / AEGIS-128X4 ciphers (crypto/aead,
// backend/libaegis), with fuzz-chosen key, AAD and ciphertext split into
// chained (possibly empty) IOBufs: decrypt, tryDecrypt and encrypt, in place
// and out of place.
//
// Input: byte 0 = cipher, byte 1 = options/fragmentation, the key+IV bytes,
// a u16-length AAD, then the ciphertext/plaintext.
#include "fuzz_common.h"

#include <fizz/crypto/test/TestUtil.h>

using namespace fizz;

namespace {

const CipherSuite kSuites[] = {
    CipherSuite::TLS_AES_128_GCM_SHA256,
    CipherSuite::TLS_AES_256_GCM_SHA384,
    CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_AEGIS_128L_SHA256,
    CipherSuite::TLS_AEGIS_256_SHA512,
    CipherSuite::TLS_AEGIS_128X2_SHA256,
    CipherSuite::TLS_AEGIS_128X4_SHA256,
};

// Splits into a chain that may include empty buffers.
std::unique_ptr<folly::IOBuf> chain(
    std::unique_ptr<folly::IOBuf> buf,
    uint8_t seed) {
  auto out = fizz_fuzz::fragment(std::move(buf), seed);
  if (seed & 0x80) {
    out->prependChain(folly::IOBuf::create(0));
    auto head = folly::IOBuf::create(0);
    head->prependChain(std::move(out));
    out = std::move(head);
  }
  return out;
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) {
    return 0;
  }
  fizz_fuzz::Reader r(data, size);
  auto suite = kSuites[r.u8() % 7];
  uint8_t opts = r.u8();
  try {
    auto aead = test::getCipher(suite);
    TrafficKey key;
    key.key = r.bytes(aead->keyLength());
    key.iv = r.bytes(aead->ivLength());
    if (key.key->length() != aead->keyLength() ||
        key.iv->length() != aead->ivLength()) {
      return 0;
    }
    Error err;
    if (aead->setKey(err, std::move(key)) != Status::Success) {
      return 0;
    }
    auto aad = r.chunk16();
    auto body = r.rest();
    uint64_t seq = opts & 0x7;
    Aead::AeadOptions options;
    if (opts & 0x8) {
      options.bufferOpt = Aead::BufferOption::AllowFullModification;
    }
    const folly::IOBuf* aadPtr = (opts & 0x10) ? nullptr : aad.get();

    folly::Optional<std::unique_ptr<folly::IOBuf>> pt;
    (void)aead->tryDecrypt(
        pt, err, chain(body->clone(), opts), aadPtr, seq, options);

    std::unique_ptr<folly::IOBuf> ct;
    Error err2;
    if (aead->encrypt(ct, err2, chain(body->clone(), opts >> 1), aadPtr, seq,
            options) == Status::Success &&
        ct) {
      std::unique_ptr<folly::IOBuf> back;
      Error err3;
      (void)aead->decrypt(back, err3, chain(std::move(ct), opts >> 2), aadPtr,
          seq, options);
    }
  } catch (const std::exception&) {
  }
  return 0;
}
