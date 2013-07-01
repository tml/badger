cmake_minimum_required ( VERSION 2.6 )

project( badger C )

set( CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/" )
find_package( LibTomCrypt REQUIRED )
find_package( Jansson REQUIRED )

list( APPEND CMAKE_C_FLAGS "-Wall -Wextra -pedantic-errors" )

include_directories( "${CMAKE_SOURCE_DIR}/include" )

set( badger_SOURCES src/badger.c )

add_library( badger SHARED ${badger_SOURCES} )

target_link_libraries( badger
  ${LibTomCrypt_LIBRARIES} ${Jansson_LIBRARIES} )

add_executable( verify verify.c )

target_link_libraries( verify badger )
