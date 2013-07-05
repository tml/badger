cmake_minimum_required ( VERSION 2.6 )

project( badger C )

set( CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/" )
find_package( LibTomCrypt REQUIRED )
find_package( Jansson REQUIRED )
find_package( CURL REQUIRED )

list( APPEND CMAKE_C_FLAGS "-Wall -Wextra -pedantic-errors" )

include_directories( "${CMAKE_SOURCE_DIR}/include" )

add_library( badger SHARED src/badger.c src/badger_err.c )
target_link_libraries( badger
  ${LibTomCrypt_LIBRARIES} ${JANSSON_LIBRARIES} ${CURL_LIBRARIES} )

add_executable( badger-record src/badger_record.c )
target_link_libraries( badger-record badger )

add_executable( badger-key src/badger_key.c )
target_link_libraries( badger-key badger )

add_executable( badger-badge src/badger_badge.c )
target_link_libraries( badger-badge badger )

add_executable( badger-verify src/badger_verify.c )
target_link_libraries( badger-verify badger )

install( FILES include/badger.h DESTINATION include )
install( TARGETS badger badger-record badger-key badger-badge badger-verify
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
)
