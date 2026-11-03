cmake_minimum_required(VERSION 3.15)
project(ProcClock VERSION 0.1.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static CRT with MSVC, so ProcClock.exe runs on a clean machine without redistributables.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(MSVC)
  add_compile_options(/W4 /utf-8 /permissive-)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)
endif()

if(WIN32)
  add_executable(ProcClock ProcClock.cpp ClockAnalysis.h)
  target_link_libraries(ProcClock PRIVATE advapi32 shell32)
  if(MINGW)
    target_link_options(ProcClock PRIVATE -static)
  endif()
endif()

# The analysis is platform independent, so the tests build and run anywhere.
option(PROCCLOCK_BUILD_TESTS "Build the ClockAnalysis tests" ON)
if(PROCCLOCK_BUILD_TESTS)
  enable_testing()
  add_executable(ClockAnalysisTests tests/ClockAnalysisTests.cpp)
  add_test(NAME ClockAnalysisTests COMMAND ClockAnalysisTests)
endif()
