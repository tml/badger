#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <curl/curl.h>
#include <getopt.h>
#include <badger.h>

void usage()
{
    printf(
        "Usage: badger_verify rpc_username badge\n"
        "Options:\n"
        "-r, --rpc   http://rpc_server_address\n"
        "-p, --pass  rpc_password\n"
    );
}

int main( const int argc, char* const* argv )
{

    int err;
    bdgr_badge badge;
    CURL* const handle = curl_easy_init();
    char* rpc_server = "http://127.0.0.1:8336";
    char* rpc_creds, * rpc_user, * rpc_pass = NULL, * badge_json;
    char* badge_id, * post_data;
    const char* const id_prefix = "nmc://badger/";
    const unsigned long int id_prefix_len = strlen( id_prefix );
    const char* const rpc_fmt = "{\"method\":\"name_show\",\"params\":[\"%s\"]}";
    const unsigned long int rpc_fmt_len = strlen( rpc_fmt ) - 2;
    unsigned long int rpc_user_len, rpc_pass_len;
    struct curl_slist *headers = 0;
    int c;
    
    while (1) {
        static struct option long_options[] = {
            { "rpc",  required_argument, 0, 'r' },
            { "pass", required_argument, 0, 'p' },
            { 0, 0, 0, 0 }
        };
        int option_index = 0;
        c = getopt_long( argc, argv, "r:u:p:", long_options, &option_index);
        if (c == -1)
            break;
        switch(c) {
        case 'r':
            rpc_user = optarg;
            rpc_user_len = strlen( rpc_user );
            break;
        case 'p':
            rpc_pass = optarg;
            rpc_pass_len = strlen( rpc_pass );
            break;
        case '?':
            break;
        default:
            abort();
        }
    }
    if( optind < argc ) {
        rpc_user = argv[ optind++ ];
    } else {
        usage();
        exit( 1 );
    }
    if( optind < argc ) {
        badge_json = argv[ optind++ ];
    } else {
        usage();
        exit( 1 );
    }
    if( optind != argc ) {
        usage();
        exit( 1 );
    }

    err = bdgr_badge_import( badge_json, &badge );
    if( err ) {
        printf( "badge import error\n" );
        exit( 1 );
    }

    if( strncmp( badge.id, id_prefix, id_prefix_len ) ) {
        printf( "badge must start with \"%s\"\n", id_prefix );
        exit( 1 );
    }
    badge_id = badge.id + id_prefix_len;

    if( rpc_pass == NULL ) {
        rpc_pass = getpass( "Enter namecoind rpc password: " );
        rpc_pass_len = strlen( rpc_pass );
    }
    rpc_creds = malloc( rpc_user_len + 1 + rpc_pass_len );
    sprintf( rpc_creds, "%s:%s", rpc_user, rpc_pass );

    headers = curl_slist_append( headers, "Content-Type: text/plain" );
    curl_easy_setopt( handle, CURLOPT_HTTPHEADER, headers );

    post_data = malloc( rpc_fmt_len + strlen( badge_id ));
    sprintf( post_data, rpc_fmt, badge_id );
    
    curl_easy_setopt( handle, CURLOPT_POSTFIELDS, post_data );

    curl_easy_setopt( handle, CURLOPT_USERPWD, rpc_creds );
    
    curl_easy_setopt( handle, CURLOPT_URL, rpc_server );
    
    curl_easy_perform( handle );

    /* import key from response object and verify badge... */

    curl_slist_free_all( headers );
    free( post_data );
    free( rpc_creds );

    return 0;
    
}
