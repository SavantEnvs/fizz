// Fuzzes fizz's client-side Encrypted Client Hello:
//  mode 0: an ECHConfigList as a client receives it (DNS HTTPS record or the
//          server's retry_configs): decode<ECHConfigList>,
//          ECHConfigContentDraft::parseSupportedECHConfig, negotiateECHConfig
//          and constructHpkeSetupResult;
//  mode 1: ech::encryptClientHello of a fuzz-supplied inner and outer
//          ClientHello against the default config (outer-extension
//          compression, calculateECHPadding over the inner hello's SNI,
//          generateGreasePSK, HPKE sealing).
//
// Input: byte 0 = mode; mode 0: the ECHConfigList; mode 1: u16-length inner
// ClientHello body, then the outer ClientHello body.
#include "fuzz_common.h"

#include <fizz/backend/openssl/crypto/exchange/X25519.h>
#include <fizz/protocol/DefaultFactory.h>
#include <fizz/protocol/ech/Encryption.h>
#include <fizz/protocol/ech/Types.h>
#include <fizz/record/Types.h>
#include <fizz/tool/FizzCommandCommon.h>

using namespace fizz;

namespace {

void configList(std::unique_ptr<folly::IOBuf> buf, const Factory& factory) {
  Error err;
  ech::ECHConfigList list;
  folly::io::Cursor cursor(buf.get());
  if (decode<ech::ECHConfigList>(list, err, cursor) != Status::Success) {
    return;
  }
  std::vector<ech::ParsedECHConfig> parsed;
  for (const auto& c : list.configs) {
    folly::Optional<ech::ParsedECHConfig> p;
    Error e;
    if (ech::ECHConfigContentDraft::parseSupportedECHConfig(p, e, c) ==
            Status::Success &&
        p) {
      parsed.push_back(std::move(*p));
    }
  }
  folly::Optional<ech::NegotiatedECHConfig> neg;
  if (ech::negotiateECHConfig(
          neg, err, parsed,
          {hpke::KEMId::x25519, hpke::KEMId::secp256r1},
          {hpke::AeadId::TLS_AES_128_GCM_SHA256,
           hpke::AeadId::TLS_AES_256_GCM_SHA384,
           hpke::AeadId::TLS_CHACHA20_POLY1305_SHA256}) != Status::Success ||
      !neg) {
    return;
  }
  std::unique_ptr<KeyExchange> kex;
  FIZZ_THROW_ON_ERROR(
      factory.makeKeyExchange(
          kex, err,
          neg->config.key_config.kem_id == hpke::KEMId::x25519
              ? NamedGroup::x25519
              : NamedGroup::secp256r1,
          KeyExchangeRole::Client),
      err);
  FIZZ_THROW_ON_ERROR(kex->generateKeyPair(err), err);
  hpke::SetupResult setup;
  (void)ech::constructHpkeSetupResult(setup, err, factory, std::move(kex), *neg);
}

void encryptHello(
    fizz_fuzz::Reader& r,
    const Factory& factory,
    const ech::NegotiatedECHConfig& config) {
  Error err;
  auto innerBuf = r.chunk16();
  auto outerBuf = r.rest();
  ClientHello inner, outer;
  folly::io::Cursor ic(innerBuf.get());
  if (decode<ClientHello>(inner, err, ic) != Status::Success) {
    return;
  }
  folly::io::Cursor oc(outerBuf.get());
  if (decode<ClientHello>(outer, err, oc) != Status::Success) {
    return;
  }
  auto kex = std::make_unique<openssl::X25519KeyExchange>();
  FIZZ_THROW_ON_ERROR(kex->generateKeyPair(err), err);
  hpke::SetupResult setup;
  FIZZ_THROW_ON_ERROR(
      ech::constructHpkeSetupResult(setup, err, factory, std::move(kex), config),
      err);
  folly::Optional<ClientPresharedKey> grease;
  (void)ech::generateGreasePSK(grease, err, inner, &factory);
  ech::OuterECHClientHello ech;
  (void)ech::encryptClientHello(
      ech, err, config, inner, outer, setup, grease,
      {ExtensionType::key_share, ExtensionType::supported_groups,
       ExtensionType::signature_algorithms});
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
  static DefaultFactory factory;
  static auto config = negotiated();
  if (size < 1) {
    return 0;
  }
  fizz_fuzz::Reader r(data, size);
  uint8_t mode = r.u8();
  try {
    if (mode & 1) {
      encryptHello(r, factory, config);
    } else {
      configList(r.rest(), factory);
    }
  } catch (const std::exception&) {
  }
  return 0;
}
