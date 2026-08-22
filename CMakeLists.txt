cmake_minimum_required(VERSION 3.16)
project(android_bwrap VERSION 3.0.3 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(ABW_ENABLE_WERROR "Treat warnings as errors" OFF)
option(ABW_BUILD_PYTHON_INTEGRATION "Build/run host-oriented Python integration suite" ON)

if(ABW_ENABLE_WERROR)
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_library(abwrap_core STATIC
  src/arch.c
  src/policy.c
  src/procfs.c
  src/remote.c
  src/seccomp_filter.c
  src/tracer.c
  src/util.c
)
target_include_directories(abwrap_core PUBLIC include)

add_executable(abwrap src/main.c)
target_link_libraries(abwrap PRIVATE abwrap_core)

install(TARGETS abwrap RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
  # These unit tests are intentionally OS-agnostic and are built natively on
  # Termux/Android as well as ordinary Linux hosts.
  add_executable(arch_unit_test tests/test_arch.c)
  target_link_libraries(arch_unit_test PRIVATE abwrap_core)
  add_test(NAME arch-unit COMMAND arch_unit_test)

  add_executable(policy_unit_test tests/test_policy.c)
  target_link_libraries(policy_unit_test PRIVATE abwrap_core)
  target_compile_options(policy_unit_test PRIVATE -UNDEBUG)
  add_test(NAME policy-unit COMMAND policy_unit_test)

  # Build syscall probes on Android too: the Termux diagnostics runner uses them.
  add_executable(raw_open_test tests/helpers/raw_open.c)
  add_executable(openat_probe_test tests/helpers/openat_probe.c)
  add_executable(fs_probe_test tests/helpers/fs_probe.c)

  # The large Python integration suite assumes a conventional GNU/Linux host
  # filesystem (/bin, /usr/bin, ...). Termux has its own native diagnostics
  # suite under tests/termux_diagnostics.sh.
  if(ABW_BUILD_PYTHON_INTEGRATION
     AND CMAKE_SYSTEM_NAME STREQUAL "Linux"
     AND NOT ANDROID)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
      add_test(NAME integration
        COMMAND ${CMAKE_COMMAND} -E env
          ABWRAP_BIN=$<TARGET_FILE:abwrap>
          RAW_OPEN_BIN=$<TARGET_FILE:raw_open_test>
          OPENAT_PROBE_BIN=$<TARGET_FILE:openat_probe_test>
          FS_PROBE_BIN=$<TARGET_FILE:fs_probe_test>
          ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_integration.py)
    endif()
  endif()
endif()
