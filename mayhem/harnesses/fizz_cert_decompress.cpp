// Fuzzes fizz's certificate decompression (RFC 8879): decode a
// CompressedCertificate message and run the decompressor for its algorithm
// (zlib or zstd; fizz's CMake build has no brotli), which inflates and then
// decodes the embedded Certificate message. This is what a client does with a
// server's compressed_certificate handshake message.
//
// Input: the CompressedCertificate handshake body.
#include "fuzz_common.h"

#include <fizz/compression/CertDecompressionManager.h>
#include <fizz/compression/ZlibCertificateDecompressor.h>
#include <fizz/compression/ZstdCertificateDecompressor.h>
#include <fizz/record/Types.h>

using namespace fizz;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static CertDecompressionManager manager(
      {std::make_shared<ZlibCertificateDecompressor>(),
       std::make_shared<ZstdCertificateDecompressor>()});
  auto body = folly::IOBuf::copyBuffer(data, size);
  try {
    CompressedCertificate cc;
    Error err;
    folly::io::Cursor cursor(body.get());
    if (decode<CompressedCertificate>(cc, err, cursor) != Status::Success) {
      return 0;
    }
    auto decompressor = manager.getDecompressor(cc.algorithm);
    if (!decompressor) {
      return 0;
    }
    CertificateMsg msg;
    if (decompressor->decompress(msg, err, cc) == Status::Success) {
      Buf out;
      Error err2;
      (void)encode(out, err2, std::move(msg));
    }
  } catch (const std::exception&) {
  }
  return 0;
}
