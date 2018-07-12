cmake_minimum_required(VERSION 3.10)
project(ICMPRateLimiting)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS -Werror)
add_executable(ICMPRateLimiting icmp_trigger.cpp include/sender_t.hpp src/sender_t.cpp include/rate_limit_sender_t.hpp include/rate_limit_sniffer_t.hpp include/rate_limit_test_t.hpp src/rate_limit_sniffer_t.cpp src/rate_limit_analyzer_t.cpp include/rate_limit_analyzer_t.hpp include/maths_utils_t.hpp src/rate_limit_estimate_t.cpp include/rate_limit_estimate_t.hpp src/rate_limit_sender_t.cpp src/rate_limit_test_t.cpp include/container_utils_t.hpp include/tins_utils_t.hpp src/markov_t.cpp include/markov_t.hpp)
target_link_libraries(ICMPRateLimiting Tins)