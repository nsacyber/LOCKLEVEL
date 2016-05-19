#LL makefile
cmake_minimum_required (VERSION 3.2)
project (locklevel)

include("locklevel.cmake")
include("debug.cmake")


set(LOCKLEVEL_MAJOR_VERSION 0)
set(LOCKLEVEL_MINOR_VERSION 1)
set(LOCKLEVEL_BUILD_VERSION 1)
set(LOCKLEVEL_VERSION ${LOCKLEVEL_MAJOR_VERSION}.${LOCKLEVEL_MINOR_VERSION}.${LOCKLEVEL_BUILD_VERSION})


#set(warnings "/W4 /WX /EHsc")
set(warnings "/W4 /EHsc")
set(sdl "/sdl")
set(cfg "/guard:cf")
# analyze does not work with v###_xp runtimes
set(analyze "/analyze")


set(PROJECT_BINARY_DIR "build/${PROJECT_NAME}")

#set C compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${warnings} ${sdl}")

if("${CMAKE_GENERATOR}" MATCHES ".*Visual Studio 14 2015.*")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${cfg}")
endif()
#end C compiler flags

#set C++ compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${warnings} ${sdl}")

if("${CMAKE_GENERATOR}" MATCHES ".*Visual Studio 14 2015.*")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${cfg}")
endif()

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MTd")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
#end C++ compiler flags

#set linker flags
if("${CMAKE_GENERATOR}" MATCHES ".*Visual Studio.*Win64.*")
	set(IS_32BIT_BUILD 0)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE,5.02")
else()
	set(IS_32BIT_BUILD 1)
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE,5.01")
endif()

if("${CMAKE_GENERATOR}" MATCHES ".*Visual Studio 14 2015.*")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${cfg}")
endif()
#end linker flags




#compiler definitions
add_definitions(-D_UNICODE)

#

include("globals.cmake")


add_subdirectory("${GET_SYSTEM_INFO_ROOT_PATH}" "${PROJECT_BINARY_DIR}/GetSystemInfo" )

add_subdirectory("${PTH_ROOT_PATH}" "${PROJECT_BINARY_DIR}/LL_PtH")
add_subdirectory("${AV_ROOT_PATH}" "${PROJECT_BINARY_DIR}/LL_AV")
add_subdirectory("${AE_ROOT_PATH}" "${PROJECT_BINARY_DIR}/LL_AE")


