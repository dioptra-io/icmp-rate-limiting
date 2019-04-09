cmake_minimum_required(VERSION 2.8)
project(ICMPRateLimiting)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

file(GLOB SOURCES src/*.cpp src/utils/*.cpp)
file(GLOB EXTERNAL_SOURCES EasyBMP_1/*.cpp)
include_directories(include)
include_directories(EasyBMP_1)

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

if(APPLE)
    # Mojave has removed /usr/local/lib from library path?
    link_directories(/usr/local/lib/)
#    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -stdlib=libc++ -lc++abi")
endif()
find_package(Boost REQUIRED COMPONENTS filesystem system iostreams program_options)


############## LOADING R ###########################################
set (RPATH "R")
set (RSCRIPT_PATH "Rscript")

set(NUM_TRUNC_CHARS 2)

execute_process(COMMAND ${RSCRIPT_PATH} -e "R.home()"
        OUTPUT_VARIABLE R_HOME)

string(REGEX MATCH \".*\" R_HOME ${R_HOME})
string(REGEX REPLACE \" "" R_HOME ${R_HOME})

message("R home is ${R_HOME}")

include_directories(${R_HOME}/include/)

if (CMAKE_HOST_WIN32)
    execute_process(COMMAND ${RSCRIPT_PATH} -e "cat(.Platform$r_arch)"
            OUTPUT_VARIABLE R_ARCH)

    execute_process(COMMAND ${RPATH} --arch ${R_ARCH} RHOME
            OUTPUT_VARIABLE R_HOME)

    string(REPLACE "\\" "/" R_HOME ${R_HOME})

    set (RPATH ${R_HOME}/bin/R)
endif()

set (RCPPFLAGS_CMD " ${RPATH} " " CMD " " config " " --cppflags ")

execute_process(COMMAND ${RPATH} CMD config --cppflags
        OUTPUT_VARIABLE RCPPFLAGS)



execute_process(COMMAND ${RSCRIPT_PATH} -e "Rcpp:::CxxFlags()"
        OUTPUT_VARIABLE RCPPINCL)
string(SUBSTRING ${RCPPINCL} ${NUM_TRUNC_CHARS} -1 RCPPINCL)
include_directories(${RCPPINCL})

execute_process(COMMAND ${RSCRIPT_PATH} -e "RInside:::CxxFlags()"
        OUTPUT_VARIABLE RINSIDEINCL)
string(SUBSTRING ${RINSIDEINCL} ${NUM_TRUNC_CHARS} -1 RINSIDEINCL)
include_directories(${RINSIDEINCL})


execute_process(COMMAND ${RSCRIPT_PATH} -e ".libPaths()[1]"
        OUTPUT_VARIABLE R_PACKAGES)

# Parse it with a regexp [1] "/usr/local/lib/R/3.5/site-library" and returns /usr/local/lib/R/3.5/site-library

string(REGEX MATCH \".*\"  R_PACKAGES ${R_PACKAGES})
string(REGEX REPLACE \" "" R_PACKAGES ${R_PACKAGES})
message("R packages installed in ${R_PACKAGES}")

set(RLDFLAGS_L ${R_HOME}/lib/)
link_directories(${RLDFLAGS_L})
set(RLDFLAGS_l -lR)

set(RINSIDELIBS_L ${R_PACKAGES}/RInside/lib/)
link_directories(${RINSIDELIBS_L})
set(RINSIDELIBS_l -lRInside)


if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
#    add_executable(ICMPPlot icmp_plot.cpp ${SOURCES} ${EXTERNAL_SOURCES})
    #add_executable(ICMPRateLimiting icmp_trigger.cpp ${SOURCES} ${EXTERNAL_SOURCES})
    add_executable(ICMPEndToEnd icmp_rate_limiting_alias_test.cpp ${SOURCES} ${EXTERNAL_SOURCES})
    add_executable(ICMPDumpRaw icmp_dump_raw.cpp ${SOURCES} ${EXTERNAL_SOURCES})

    #target_link_libraries(ICMPRateLimiting pthread tins ${Boost_LIBRARIES})
#    target_link_libraries(ICMPPlot pthread tins ${Boost_LIBRARIES})
    target_link_libraries(ICMPEndToEnd pthread tins ${Boost_LIBRARIES} ${RINSIDELIBS_l} ${RLDFLAGS_l})
    target_link_libraries(ICMPDumpRaw pthread tins ${Boost_LIBRARIES}  ${RINSIDELIBS_l} ${RLDFLAGS_l})

endif()

#add_executable(StatsAlgoTest src/test/math_utils_test_t.cpp)