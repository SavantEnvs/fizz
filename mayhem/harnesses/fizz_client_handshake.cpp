// Fuzzes fizz's TLS 1.3 client: a FizzClient sends its ClientHello, then
// ClientStateMachine::processSocketData reads the fuzz input as the server's
// bytes (ServerHello / HelloRetryRequest and what follows, alerts, record
// framing). Covers the plaintext record layer, ServerHello/HRR decoding,
// negotiation checks, key-share handling, cookie echo, ECH acceptance/retry
// checks (half the inputs connect with an ECH config) and the key schedule.
//
// Input: byte 0 picks options and fragmentation, byte 1 the split point of
// the server stream into two writes, the rest is the server stream.
#include "fuzz_common.h"

#include <functional>

#include <folly/io/async/EventBase.h>

#include <fizz/fizz-config.h>
#if !FIZZ_HAVE_OQS
#error "fizz must be built with liboqs (FIZZ_HAVE_OQS) for the X25519MLKEM768 group"
#endif
#include <fizz/client/FizzClient.h>
#include <fizz/client/FizzClientContext.h>
#include <fizz/tool/FizzCommandCommon.h>

using namespace fizz;
using namespace fizz::client;

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

class Client : public folly::DelayedDestruction {
 public:
  Client() : fizz_(state_, queue_, readAeadOptions_, visitor_, this) {
    visitor_.state = &state_;
    visitor_.waitForData = [this] { fizz_.waitForData(); };
  }
  State state_;
  folly::IOBufQueue queue_{folly::IOBufQueue::cacheChainLength()};
  Aead::AeadOptions readAeadOptions_;
  Visitor visitor_;
  FizzClient<Visitor> fizz_;
};

std::shared_ptr<FizzClientContext> makeContext() {
  auto ctx = std::make_shared<FizzClientContext>();
  ctx->setSupportedVersions(
      {ProtocolVersion::tls_1_3, ProtocolVersion::tls_1_3_28});
  ctx->setSupportedCiphers(
      {CipherSuite::TLS_AES_128_GCM_SHA256,
       CipherSuite::TLS_AES_256_GCM_SHA384,
       CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
       CipherSuite::TLS_AEGIS_128L_SHA256});
  // X25519MLKEM768 is the hybrid PQ group upstream's own client context
  // offers by default when built with liboqs (FizzClientContext.h).
  ctx->setSupportedGroups(
      {NamedGroup::X25519MLKEM768,
       NamedGroup::x25519,
       NamedGroup::secp256r1,
       NamedGroup::secp384r1});
  ctx->setDefaultShares({NamedGroup::X25519MLKEM768, NamedGroup::x25519});
  ctx->setSupportedAlpns({"h2", "http/1.1"});
  return ctx;
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static auto ctx = makeContext();
  static auto echConfigs = tool::getDefaultECHConfigs();
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
  std::unique_ptr<Client, folly::DelayedDestruction::Destructor> client(
      new Client());
  try {
    folly::Optional<std::vector<ech::ParsedECHConfig>> ech;
    if (opts & 1) {
      ech = echConfigs;
    }
    client->fizz_.connect(
        ctx,
        nullptr,
        std::string("fizz.example.com"),
        folly::none,
        std::move(ech));
    evb.loop();
    folly::io::Cursor c(stream.get());
    std::unique_ptr<folly::IOBuf> first, second;
    c.clone(first, cut);
    c.clone(second, len - cut);
    client->queue_.append(fizz_fuzz::fragment(std::move(first), opts >> 1));
    client->fizz_.newTransportData();
    evb.loop();
    if (!client->fizz_.inErrorState() && second->length() > 0) {
      client->queue_.append(fizz_fuzz::fragment(std::move(second), opts >> 1));
      client->fizz_.newTransportData();
      evb.loop();
    }
  } catch (const std::exception&) {
  }
  client.reset();
  evb.loop();
  return 0;
}
