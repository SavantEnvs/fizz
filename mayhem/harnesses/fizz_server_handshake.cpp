// Fuzzes fizz's TLS 1.3 server: a FizzServer driven by
// ServerStateMachine::processSocketData reads the fuzz input as the bytes a
// client sends on the socket (ClientHello, HRR retry, early data, alerts...).
// Covers the plaintext record layer, ClientHello and extension decoding,
// version/cipher/group negotiation, cookies, PSK/ticket handling, client-auth
// and the ECH decrypter (a default ECH config is installed, so an
// encrypted_client_hello extension reaches HPKE decryption).
//
// Input: byte 0 picks a fragmentation pattern and server options, the rest is
// the client's byte stream, fed in two writes split at a fuzz-chosen offset.
#include "fuzz_common.h"

#include <functional>

#include <folly/io/async/EventBase.h>

#include <fizz/protocol/DefaultFactory.h>
#include <fizz/protocol/ech/Decrypter.h>
#include <fizz/server/AeadCookieCipher.h>
#include <fizz/server/AeadTicketCipher.h>
#include <fizz/server/CookieTypes.h>
#include <fizz/server/DefaultCertManager.h>
#include <fizz/server/FizzServer.h>
#include <fizz/server/TicketCodec.h>
#include <fizz/tool/FizzCommandCommon.h>
#include <fizz/backend/openssl/crypto/exchange/X25519.h>
#include <folly/String.h>

using namespace fizz;
using namespace fizz::server;

namespace {

// Applies the state machine's actions the way AsyncFizz{Client,Server} do:
// state mutations are applied, WaitForData pauses processing until more
// transport data arrives, everything else (writes, app data, errors) is
// dropped.
struct Visitor {
  State* state{nullptr};
  std::function<void()> waitForData;
  void operator()(MutateState& mutate) {
    mutate(*state);
  }
  void operator()(WaitForData&) {
    waitForData();
  }
  template <typename T>
  void operator()(T&) {}
};

class Server : public folly::DelayedDestruction {
 public:
  Server() : fizz_(state_, queue_, readAeadOptions_, visitor_, this) {
    visitor_.state = &state_;
    visitor_.waitForData = [this] { fizz_.waitForData(); };
  }
  State state_;
  folly::IOBufQueue queue_{folly::IOBufQueue::cacheChainLength()};
  Aead::AeadOptions readAeadOptions_;
  Visitor visitor_;
  FizzServer<Visitor> fizz_;
};

std::shared_ptr<ech::Decrypter> makeDecrypter() {
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

std::shared_ptr<FizzServerContext> makeContext(bool clientAuth) {
  auto ctx = std::make_shared<FizzServerContext>();
  auto certManager = std::make_shared<DefaultCertManager>();
  certManager->addCertAndSetDefault(fizz_fuzz::p256SelfCert());
  ctx->setCertManager(certManager);
  ctx->setSupportedVersions(
      {ProtocolVersion::tls_1_3, ProtocolVersion::tls_1_3_28});
  ctx->setSupportedCiphers(
      {{CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256},
       {CipherSuite::TLS_AEGIS_128L_SHA256}});
  ctx->setSupportedAlpns({"h2", "http/1.1"});
  ctx->setVersionFallbackEnabled(true);
  ctx->setEarlyDataSettings(
      true, {std::chrono::seconds(-10), std::chrono::seconds(10)}, nullptr);
  if (clientAuth) {
    ctx->setClientAuthMode(ClientAuthMode::Optional);
  }

  auto ticketCipher = std::make_shared<Aead128GCMTicketCipher<
      TicketCodec<CertificateStorage::X509>>>(
      std::make_shared<DefaultFactory>(), certManager);
  static const std::string kTicketSecret(32, 't');
  std::vector<folly::ByteRange> ticketSecrets{folly::StringPiece(kTicketSecret)};
  ticketCipher->setTicketSecrets(ticketSecrets);
  ctx->setTicketCipher(ticketCipher);

  auto tokenCipher = std::make_unique<Aead128GCMTokenCipher>(
      std::vector<std::string>({"Fizz Cookie Cipher v1"}));
  auto cookieCipher =
      std::make_shared<AES128CookieCipher>(std::move(tokenCipher));
  static const std::string kCookieSecret(32, 'c');
  std::vector<folly::ByteRange> cookieSecrets{folly::StringPiece(kCookieSecret)};
  cookieCipher->setCookieSecrets(cookieSecrets);
  cookieCipher->setContext(ctx.get());
  ctx->setCookieCipher(cookieCipher);

  ctx->setECHDecrypter(makeDecrypter());
  return ctx;
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static auto ctxNoAuth = makeContext(false);
  static auto ctxAuth = makeContext(true);
  if (size < 3) {
    return 0;
  }
  fizz_fuzz::Reader r(data, size);
  uint8_t opts = r.u8();
  uint8_t split = r.u8();
  auto stream = r.rest();
  size_t len = stream->computeChainDataLength();
  size_t cut = len * split / 256;

  folly::EventBase evb;
  std::unique_ptr<Server, folly::DelayedDestruction::Destructor> server(
      new Server());
  try {
    server->fizz_.accept(&evb, (opts & 1) ? ctxAuth : ctxNoAuth);
    evb.loop();
    folly::io::Cursor c(stream.get());
    std::unique_ptr<folly::IOBuf> first, second;
    c.clone(first, cut);
    c.clone(second, len - cut);
    server->queue_.append(fizz_fuzz::fragment(std::move(first), opts >> 1));
    server->fizz_.newTransportData();
    evb.loop();
    if (!server->fizz_.inErrorState() && second->length() > 0) {
      server->queue_.append(fizz_fuzz::fragment(std::move(second), opts >> 1));
      server->fizz_.newTransportData();
      evb.loop();
    }
  } catch (const std::exception&) {
  }
  server.reset();
  evb.loop();
  return 0;
}
