// Fuzzes the ECH configuration parsing of the fizz command-line tool
// (tool/FizzCommandCommon.cpp): parseECHConfigs over a JSON document (as read
// from the --echconfigs file) and parseECHConfigsBase64 over a base64
// ECHConfigList (as passed with --echbase64).
//
// Input: byte 0 = mode, then the JSON text or the base64 string.
#include "fuzz_common.h"

#include <folly/json/json.h>

#include <fizz/tool/FizzCommandCommon.h>

using namespace fizz;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fizz_fuzz::quietLogs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) {
    return 0;
  }
  std::string text(reinterpret_cast<const char*>(data) + 1, size - 1);
  try {
    if (data[0] & 1) {
      folly::Optional<std::vector<ech::ParsedECHConfig>> configs;
      Error err;
      (void)tool::parseECHConfigsBase64(configs, err, text);
    } else {
      folly::json::serialization_opts opts;
      opts.recursion_limit = 64;
      auto json = folly::parseJson(text, opts);
      (void)tool::parseECHConfigs(std::move(json));
    }
  } catch (const std::exception&) {
  }
  return 0;
}
