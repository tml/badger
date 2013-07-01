#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <curl/curl.h>
#include <badger.h>

int main( const int argc, const char** argv )
{

    CURL* handle = curl_easy_init();
    
    if( argc != 2 ) {
        printf( "Use: %s \"<BadgeJSONString>\"\n", argv[0] );
    }

    curl_easy_setopt( handle, CURLOPT_URL, argv[1] );

    
    
    return 0;
    
}
