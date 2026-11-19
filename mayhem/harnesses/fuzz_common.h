// Shared helpers for the fizz fuzz harnesses (mayhem/harnesses/fizz_*.cpp).
//
// State kept across inputs on purpose: test certificates/keys, contexts and
// configs built once from constants (read-only for the fuzzed code), and the
// glog verbosity, which no input can change.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <folly/io/IOBuf.h>
#include <folly/io/IOBufQueue.h>
#include <folly/ssl/OpenSSLCertUtils.h>
#include <glog/logging.h>

#include <fizz/backend/openssl/certificate/CertUtils.h>
#include <fizz/crypto/test/TestKeys.h>
#include <fizz/protocol/Certificate.h>

namespace fizz_fuzz {

inline void quietLogs() {
  static bool done = [] {
    FLAGS_minloglevel = 3; // FATAL only
    FLAGS_logtostderr = true;
    return true;
  }();
  (void)done;
}

// Splits a fuzz input into pieces without rejecting anything.
class Reader {
 public:
  Reader(const uint8_t* data, size_t size) : p_(data), n_(size) {}

  size_t remaining() const {
    return n_;
  }

  uint8_t u8() {
    if (n_ == 0) {
      return 0;
    }
    uint8_t v = *p_;
    p_++;
    n_--;
    return v;
  }

  uint16_t u16() {
    uint16_t hi = u8();
    return static_cast<uint16_t>((hi << 8) | u8());
  }

  // A chunk of up to `len` bytes.
  std::unique_ptr<folly::IOBuf> bytes(size_t len) {
    if (len > n_) {
      len = n_;
    }
    auto buf = folly::IOBuf::copyBuffer(p_, len);
    p_ += len;
    n_ -= len;
    return buf;
  }

  // A 16-bit length prefixed chunk.
  std::unique_ptr<folly::IOBuf> chunk16() {
    return bytes(u16());
  }

  std::unique_ptr<folly::IOBuf> rest() {
    return bytes(n_);
  }

 private:
  const uint8_t* p_;
  size_t n_;
};

// Splits `buf` into a chain of IOBufs at fuzz-chosen points, so the code
// under test sees fragmented input the way a socket delivers it.
inline std::unique_ptr<folly::IOBuf> fragment(
    std::unique_ptr<folly::IOBuf> buf,
    uint8_t seed) {
  buf->coalesce();
  size_t len = buf->length();
  if (seed == 0 || len < 2) {
    return buf;
  }
  std::unique_ptr<folly::IOBuf> out;
  size_t off = 0;
  size_t step = (seed % 61) + 1;
  while (off < len) {
    size_t n = std::min(step, len - off);
    auto piece = folly::IOBuf::copyBuffer(buf->data() + off, n);
    if (out) {
      out->prependChain(std::move(piece));
    } else {
      out = std::move(piece);
    }
    off += n;
    step = ((step * 7 + seed) % 97) + 1;
  }
  return out;
}

inline std::shared_ptr<fizz::SelfCert> p256SelfCert() {
  std::unique_ptr<fizz::SelfCert> cert;
  fizz::Error err;
  FIZZ_THROW_ON_ERROR(
      fizz::openssl::CertUtils::makeSelfCert(
          cert,
          err,
          fizz::test::kP256Certificate.str(),
          fizz::test::kP256Key.str()),
      err);
  return std::shared_ptr<fizz::SelfCert>(std::move(cert));
}

inline std::shared_ptr<const fizz::PeerCert> p256PeerCert() {
  auto certs = folly::ssl::OpenSSLCertUtils::readCertsFromBuffer(
      fizz::test::kP256Certificate);
  std::unique_ptr<fizz::PeerCert> ret;
  fizz::Error err;
  FIZZ_THROW_ON_ERROR(
      fizz::openssl::CertUtils::makePeerCert(ret, err, std::move(certs[0])),
      err);
  return std::shared_ptr<const fizz::PeerCert>(std::move(ret));
}

} // namespace fizz_fuzz
