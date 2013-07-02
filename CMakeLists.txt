cmake_minimum_required ( VERSION 2.6 )

project( badger C )

set( CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/" )
find_package( LibTomCrypt REQUIRED )
find_package( Jansson REQUIRED )
find_package( CURL )

list( APPEND CMAKE_C_FLAGS "-Wall -Wextra -pedantic-errors" )

include_directories( "${CMAKE_SOURCE_DIR}/include" )

add_library( badger SHARED src/badger.c )
target_link_libraries( badger
  ${LibTomCrypt_LIBRARIES} ${JANSSON_LIBRARIES} )

add_executable( badger_key src/badger_key.c )
target_link_libraries( badger_key badger )

add_executable( badger_record src/badger_record.c )
target_link_libraries( badger_record badger ${JANSSON_LIBRARIES} )

add_executable( badger_badge src/badger_badge.c )
target_link_libraries( badger_badge badger ${LibTomCrypt_LIBRARIES} )

if( CURL_FOUND )
  
  add_executable( badger_verify src/badger_verify.c )
  target_link_libraries( badger_verify badger ${CURL_LIBRARIES} ${JANSSON_LIBRARIES} )
  
endif( CURL_FOUND )
