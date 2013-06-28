cmake_minimum_required ( VERSION 2.6 )

project( badger C )

list( APPEND CMAKE_C_FLAGS "-Wall -Wextra -pedantic-errors" )

set( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/" )

find_package( LibTomCrypt )

include_directories( "${CMAKE_SOURCE_DIR}/include" )

set( badger_SOURCES
  src/badger.c
  src/test_key.c
  )

add_library( badger SHARED ${badger_SOURCES} )

target_link_libraries( badger ${LibTomCrypt_LIBRARIES} )

add_executable( badgerd badgerd.c )

target_link_libraries( badgerd badger )
