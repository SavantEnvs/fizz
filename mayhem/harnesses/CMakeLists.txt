# Fuzz-harness build for fizz: pulls upstream's own fizz/CMakeLists.txt in as a
# subdirectory (so libfizz and fizz_test_support are built exactly as upstream
# builds them, with the sanitizer flags from mayhem/build.sh), then links one
# libFuzzer binary and one standalone reproducer per mayhem/harnesses/fizz_*.cpp.
cmake_minimum_required(VERSION 3.14)
project(fizz_mayhem LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(FIZZ_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../fizz")
# folly's imported targets are directory-scoped; find it here too so the
# harness targets below can name them.
find_package(folly CONFIG REQUIRED)
add_subdirectory("${FIZZ_ROOT}" fizz)

set(LIB_FUZZING_ENGINE "-fsanitize=fuzzer" CACHE STRING "libFuzzer link flag")
set(STANDALONE_MAIN_OBJ "" CACHE FILEPATH "pre-compiled StandaloneFuzzTargetMain.o")
set(LSAN_OFF_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../lsan_off.cc" CACHE FILEPATH "__lsan_is_turned_off TU")
set(HARNESS_OUT_DIR "${CMAKE_BINARY_DIR}/out" CACHE PATH "where the binaries go")

file(GLOB HARNESSES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/fizz_*.cpp")

# tool/FizzCommandCommon.cpp holds the ECH-config parsing the fizz CLI uses;
# upstream only compiles it into the tool and its test, so we do the same.
add_library(fizz_mayhem_common STATIC
  "${FIZZ_ROOT}/tool/FizzCommandCommon.cpp")
target_link_libraries(fizz_mayhem_common PUBLIC
  fizz fizz_test_support Folly::folly)

foreach(src ${HARNESSES})
  get_filename_component(name "${src}" NAME_WE)
  foreach(kind fuzz standalone)
    if(kind STREQUAL "fuzz")
      set(tgt "${name}")
    else()
      set(tgt "${name}-standalone")
    endif()
    # lsan_off.cc goes into each binary directly: from a static library the
    # linker would not pull it in (the runtime's weak definition satisfies it).
    add_executable(${tgt} "${src}" "${LSAN_OFF_SRC}")
    target_link_libraries(${tgt} PRIVATE fizz_mayhem_common)
    set_target_properties(${tgt} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${HARNESS_OUT_DIR}")
    if(kind STREQUAL "fuzz")
      target_link_options(${tgt} PRIVATE ${LIB_FUZZING_ENGINE})
    else()
      target_sources(${tgt} PRIVATE "${STANDALONE_MAIN_OBJ}")
    endif()
  endforeach()
endforeach()
