cmake_minimum_required(VERSION 2.8)
project(ICMPRateLimiting)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS -Werror)

file(GLOB SOURCES src/*.cpp src/utils/*.cpp)
file(GLOB EXTERNAL_SOURCES EasyBMP_1/*.cpp)
include_directories(include)
include_directories(EasyBMP_1)

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost REQUIRED COMPONENTS filesystem system iostreams program_options)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
#    add_executable(ICMPPlot icmp_plot.cpp ${SOURCES} ${EXTERNAL_SOURCES})
    #add_executable(ICMPRateLimiting icmp_trigger.cpp ${SOURCES} ${EXTERNAL_SOURCES})
    add_executable(ICMPEndToEnd icmp_rate_limiting_alias_test.cpp ${SOURCES} ${EXTERNAL_SOURCES})
    add_executable(ICMPDumpRaw icmp_dump_raw.cpp ${SOURCES} ${EXTERNAL_SOURCES})

    #target_link_libraries(ICMPRateLimiting pthread tins ${Boost_LIBRARIES})
#    target_link_libraries(ICMPPlot pthread tins ${Boost_LIBRARIES})
    target_link_libraries(ICMPEndToEnd pthread tins ${Boost_LIBRARIES})
    target_link_libraries(ICMPDumpRaw pthread tins ${Boost_LIBRARIES})

endif()

#add_executable(StatsAlgoTest src/test/math_utils_test_t.cpp)