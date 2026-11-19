// Fuzzes fizz's read record layers: PlaintextReadRecordLayer and
// EncryptedReadRecordLayer, through ReadRecordLayer::readEvent (record
// framing, fragment reassembly, handshake-message splitting and decoding into
// events, TLSInnerPlaintext content-type/padding parsing).
//
// For the encrypted layer the harness plays the peer: it seals each
// fuzz-supplied TLSInnerPlaintext with the same fixed traffic key, so the
// decrypted-content parsing is reached instead of every record failing
// authentication. Raw (unsealed) fuzz bytes can follow.
//
// Input: byte 0 = mode bits, byte 1 = cipher; then for the encrypted mode a
// list of [u16 length][inner plaintext] records, the rest raw.
#include "fuzz_common.h"

#include <fizz/crypto/test/TestUtil.h>
#include <fizz/record/EncryptedRecordLayer.h>
#include <fizz/record/PlaintextRecordLayer.h>

using namespace fizz;

namespace {

const CipherSuite kSuites[] = {
    CipherSuite::TLS_AES_128_GCM_SHA256,
    CipherSuite::TLS_AES_256_GCM_SHA384,
    CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
    CipherSuite::TLS_AEGIS_128L_SHA256,
};

std::unique_ptr<Aead> makeAead(CipherSuite suite) {
  auto aead = test::getCipher(suite);
  TrafficKey key;
  key.key = folly::IOBuf::create(aead->keyLength());
  memset(key.key->writableData(), 0x4b, aead->keyLength());
  key.key->append(aead->keyLength());
  key.iv = folly::IOBuf::create(aead->ivLength());
  memset(key.iv->writableData(), 0x17, aead->ivLength());
  key.iv->append(aead->ivLength());
  Error err;
  FIZZ_THROW_ON_ERROR(aead->setKey(err, std::move(key)), err);
  return aead;
}

void drain(ReadRecordLayer& rl, folly::IOBufQueue& q) {
  for (int i = 0; i < 256; i++) {
    ReadRecordLayer::ReadResult<Param> ev;
    Error err;
    if (rl.readEvent(ev, err, q, Aead::AeadOptions()) != Status::Success) {
      return;
    }
    if (!ev.has_value()) {
      return;
    }
  }
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
  uint8_t mode = r.u8();
  uint8_t cipher = r.u8();
  folly::IOBufQueue q{folly::IOBufQueue::cacheChainLength()};
  try {
    if ((mode & 1) == 0) {
      PlaintextReadRecordLayer rl;
      rl.setSkipEncryptedRecords(mode & 2);
      q.append(fizz_fuzz::fragment(r.rest(), mode >> 2));
      drain(rl, q);
      return 0;
    }

    auto suite = kSuites[cipher % 4];
    auto sealer = makeAead(suite);
    EncryptedReadRecordLayer rl(EncryptionLevel::AppTraffic);
    Error err;
    FIZZ_THROW_ON_ERROR(
        rl.setAead(err, folly::ByteRange(), makeAead(suite)), err);
    rl.setSkipFailedDecryption(mode & 2);

    std::unique_ptr<folly::IOBuf> wire = folly::IOBuf::create(0);
    uint64_t seq = 0;
    size_t records = (mode >> 2) & 0x7;
    for (size_t i = 0; i < records && r.remaining() > 0; i++) {
      auto inner = r.chunk16();
      size_t ctLen = inner->computeChainDataLength() + sealer->getCipherOverhead();
      if (ctLen > 0xffff) {
        break;
      }
      auto header = folly::IOBuf::create(5);
      uint8_t* h = header->writableData();
      h[0] = static_cast<uint8_t>(ContentType::application_data);
      h[1] = 0x03;
      h[2] = 0x03;
      h[3] = static_cast<uint8_t>(ctLen >> 8);
      h[4] = static_cast<uint8_t>(ctLen);
      header->append(5);
      std::unique_ptr<folly::IOBuf> sealed;
      FIZZ_THROW_ON_ERROR(
          sealer->encrypt(
              sealed, err, std::move(inner), header.get(), seq++,
              Aead::AeadOptions()),
          err);
      wire->prependChain(std::move(header));
      wire->prependChain(std::move(sealed));
    }
    wire->prependChain(r.rest());
    q.append(fizz_fuzz::fragment(std::move(wire), mode >> 5));
    drain(rl, q);
  } catch (const std::exception&) {
  }
  return 0;
}
