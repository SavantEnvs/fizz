// Fuzzes fizz's server-side Encrypted Client Hello: ech::ECHConfigManager::
// decryptClientHello (config matching, HPKE decapsulation and opening) and
// what follows decryption in Encryption.cpp (decoding the inner ClientHello,
// padding checks, ech_outer_extensions substitution against the outer hello,
// re-encoding).
//
// The harness plays an ECH client for the server's default config (the one
// the fizz CLI ships, with its known X25519 key): it decodes a fuzz-supplied
// outer ClientHello, attaches an encrypted_client_hello extension and seals
// the fuzz-supplied EncodedClientHelloInner bytes with HPKE against the
// AAD the server will recompute. So the bytes the server decrypts are the
// fuzzer's, not something that always fails authentication.
//
// Input: byte 0 = mode (bit 0: hand the outer hello to the decrypter as-is,
// unsealed), u16-length outer ClientHello body, then the inner plaintext.
#include "fuzz_common.h"

#include <fizz/backend/openssl/crypto/exchange/X25519.h>
#include <fizz/crypto/hpke/Utils.h>
#include <fizz/protocol/DefaultFactory.h>
#include <fizz/protocol/ech/Decrypter.h>
#include <fizz/protocol/ech/Encryption.h>
#include <fizz/record/Extensions.h>
#include <fizz/record/Types.h>
#include <fizz/tool/FizzCommandCommon.h>
#include <folly/String.h>

using namespace fizz;

namespace {

std::shared_ptr<ech::ECHConfigManager> makeDecrypter() {
  auto priv = folly::IOBuf::copyBuffer(folly::unhexlify(
      "8c490e5b0c7dbe0c6d2192484d2b7a0423b3b4544f2481095a99dbf238fb350f"));
  auto kex = std::make_unique<openssl::X25519KeyExchange>();
  Error err;
  FIZZ_THROW_ON_ERROR(kex->setPrivateKey(err, std::move(priv)), err);
  auto decrypter =
      std::make_shared<ech::ECHConfigManager>(std::make_shared<DefaultFactory>());
  decrypter->addDecryptionConfig(
      ech::DecrypterParams{tool::getDefaultECHConfigs()[0], std::move(kex)});
  return decrypter;
}

ech::NegotiatedECHConfig negotiated() {
  folly::Optional<ech::NegotiatedECHConfig> ret;
  Error err;
  FIZZ_THROW_ON_ERROR(
      ech::negotiateECHConfig(
          ret, err, tool::getDefaultECHConfigs(), {hpke::KEMId::x25519},
          {hpke::AeadId::TLS_AES_128_GCM_SHA256}),
      err);
  return std::move(*ret);
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static auto decrypter = makeDecrypter();
  static auto config = negotiated();
  static DefaultFactory factory;
  if (size < 3) {
    return 0;
  }
  fizz_fuzz::Reader r(data, size);
  uint8_t mode = r.u8();
  auto outerBuf = r.chunk16();
  auto inner = r.rest();
  try {
    Error err;
    ClientHello outer;
    folly::io::Cursor cursor(outerBuf.get());
    if (decode<ClientHello>(outer, err, cursor) != Status::Success) {
      return 0;
    }
    if (!(mode & 1)) {
      // Replace any ECH extension with one sealing `inner`.
      outer.extensions.erase(
          std::remove_if(
              outer.extensions.begin(), outer.extensions.end(),
              [](const Extension& e) {
                return e.extension_type == ExtensionType::encrypted_client_hello;
              }),
          outer.extensions.end());
      auto kex = std::make_unique<openssl::X25519KeyExchange>();
      FIZZ_THROW_ON_ERROR(kex->generateKeyPair(err), err);
      hpke::SetupResult setup;
      FIZZ_THROW_ON_ERROR(
          ech::constructHpkeSetupResult(
              setup, err, factory, std::move(kex), config),
          err);
      size_t overhead;
      FIZZ_THROW_ON_ERROR(
          hpke::getCipherOverhead(overhead, err, config.cipherSuite.aead_id),
          err);
      ech::OuterECHClientHello ech;
      ech.cipher_suite = config.cipherSuite;
      ech.config_id = config.configId;
      ech.enc = setup.enc->clone();
      size_t payloadLen = inner->computeChainDataLength() + overhead;
      ech.payload = folly::IOBuf::create(payloadLen);
      memset(ech.payload->writableData(), 0, payloadLen);
      ech.payload->append(payloadLen);
      Extension ext;
      FIZZ_THROW_ON_ERROR(encodeExtension(ext, err, ech), err);
      outer.extensions.push_back(std::move(ext));
      Buf aad;
      FIZZ_THROW_ON_ERROR(encode(aad, err, outer.clone()), err);
      FIZZ_THROW_ON_ERROR(
          setup.context->seal(ech.payload, err, aad.get(), std::move(inner)),
          err);
      FIZZ_THROW_ON_ERROR(encodeExtension(outer.extensions.back(), err, ech),
          err);
    }
    folly::Optional<ech::DecrypterResult> result;
    if (decrypter->decryptClientHello(result, err, outer) == Status::Success &&
        result) {
      Buf out;
      Error err2;
      (void)encode(out, err2, std::move(result->chlo));
    }
  } catch (const std::exception&) {
  }
  return 0;
}
