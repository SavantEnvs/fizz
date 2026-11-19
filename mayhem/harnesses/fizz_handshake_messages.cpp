// Fuzzes fizz's TLS 1.3 handshake-message decoders (fizz::decode<T>) and every
// extension parser (fizz::getExtension<T>), including the ones a peer only
// sends after encryption (EncryptedExtensions, Certificate,
// CompressedCertificate, CertificateRequest, CertificateVerify,
// NewSessionTicket), the ECH extensions, delegated credentials and token
// binding. Decoded messages are re-encoded.
//
// Input: byte 0 picks the message type, the rest is the handshake body.
#include "fuzz_common.h"

#include <fizz/extensions/delegatedcred/Types.h>
#include <fizz/extensions/tokenbinding/Types.h>
#include <fizz/protocol/ech/ECHExtensions.h>
#include <fizz/record/Extensions.h>
#include <fizz/record/Types.h>

using namespace fizz;

namespace {

template <class T>
void tryExt(const std::vector<Extension>& exts) {
  folly::Optional<T> ext;
  Error err;
  try {
    if (getExtension<T>(ext, err, exts) == Status::Success && ext) {
      Extension out;
      Error err2;
      (void)encodeExtension(out, err2, *ext);
    }
  } catch (const std::exception&) {
  }
}

void allExtensions(const std::vector<Extension>& exts) {
  try {
    tryExt<SignatureAlgorithms>(exts);
    tryExt<SupportedGroups>(exts);
    tryExt<ClientKeyShare>(exts);
    tryExt<ServerKeyShare>(exts);
    tryExt<HelloRetryRequestKeyShare>(exts);
    tryExt<ClientPresharedKey>(exts);
    tryExt<ServerPresharedKey>(exts);
    tryExt<ClientEarlyData>(exts);
    tryExt<ServerEarlyData>(exts);
    tryExt<TicketEarlyData>(exts);
    tryExt<Cookie>(exts);
    tryExt<SupportedVersions>(exts);
    tryExt<ServerSupportedVersions>(exts);
    tryExt<PskKeyExchangeModes>(exts);
    tryExt<ProtocolNameList>(exts);
    tryExt<ServerNameList>(exts);
    tryExt<CertificateAuthorities>(exts);
    tryExt<CertificateCompressionAlgorithms>(exts);
    tryExt<ech::OuterECHClientHello>(exts);
    tryExt<ech::InnerECHClientHello>(exts);
    tryExt<ech::ECHEncryptedExtensions>(exts);
    tryExt<ech::ECHHelloRetryRequest>(exts);
    tryExt<ech::OuterExtensions>(exts);
    tryExt<extensions::DelegatedCredential>(exts);
    tryExt<extensions::DelegatedCredentialSupport>(exts);
    tryExt<extensions::TokenBindingParameters>(exts);
  } catch (const std::exception&) {
  }
}

template <class T>
bool decodeMsg(T& msg, const std::unique_ptr<folly::IOBuf>& body) {
  folly::io::Cursor cursor(body.get());
  Error err;
  try {
    return decode<T>(msg, err, cursor) == Status::Success;
  } catch (const std::exception&) {
    return false;
  }
}

template <class T>
void reencode(T&& msg) {
  Buf out;
  Error err;
  try {
    (void)encode(out, err, std::forward<T>(msg));
  } catch (const std::exception&) {
  }
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) {
    return 0;
  }
  uint8_t sel = data[0];
  auto body = folly::IOBuf::copyBuffer(data + 1, size - 1);
  switch (sel % 14) {
    case 0: {
      ClientHello m;
      if (decodeMsg(m, body)) {
        allExtensions(m.extensions);
        try {
          size_t binderLen = 0;
          Error err;
          (void)getBinderLength(binderLen, err, m);
        } catch (const std::exception&) {
        }
        reencode(std::move(m));
      }
      break;
    }
    case 1: {
      ServerHello m;
      if (decodeMsg(m, body)) {
        allExtensions(m.extensions);
        reencode(std::move(m));
      }
      break;
    }
    case 2: {
      EncryptedExtensions m;
      if (decodeMsg(m, body)) {
        allExtensions(m.extensions);
        reencode(std::move(m));
      }
      break;
    }
    case 3: {
      CertificateMsg m;
      if (decodeMsg(m, body)) {
        for (auto& entry : m.certificate_list) {
          allExtensions(entry.extensions);
        }
        reencode(std::move(m));
      }
      break;
    }
    case 4: {
      CompressedCertificate m;
      if (decodeMsg(m, body)) {
        reencode(std::move(m));
      }
      break;
    }
    case 5: {
      CertificateRequest m;
      if (decodeMsg(m, body)) {
        allExtensions(m.extensions);
        reencode(std::move(m));
      }
      break;
    }
    case 6: {
      CertificateVerify m;
      if (decodeMsg(m, body)) {
        reencode(std::move(m));
      }
      break;
    }
    case 7: {
      NewSessionTicket m;
      if (decodeMsg(m, body)) {
        allExtensions(m.extensions);
        reencode(std::move(m));
      }
      break;
    }
    case 8: {
      KeyUpdate m;
      if (decodeMsg(m, body)) {
        reencode(std::move(m));
      }
      break;
    }
    case 9: {
      Alert m;
      if (decodeMsg(m, body)) {
        reencode(std::move(m));
      }
      break;
    }
    case 10: {
      EndOfEarlyData m;
      (void)decodeMsg(m, body);
      break;
    }
    case 11: {
      // Bare extension list, as it appears in any of the messages above.
      ClientHello m;
      m.legacy_session_id = folly::IOBuf::create(0);
      try {
        folly::io::Cursor cursor(body.get());
        Error err;
        size_t len;
        if (detail::readVector<uint16_t>(len, err, m.extensions, cursor) ==
            Status::Success) {
          allExtensions(m.extensions);
        }
      } catch (const std::exception&) {
      }
      break;
    }
    case 12: {
      extensions::TokenBindingMessage m;
      if (decodeMsg(m, body)) {
        reencode(std::move(m));
      }
      break;
    }
    case 13: {
      Finished m;
      try {
        Error err;
        (void)decode<Finished>(m, err, body->clone());
      } catch (const std::exception&) {
      }
      break;
    }
  }
  return 0;
}
