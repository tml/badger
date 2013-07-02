#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <curl/curl.h>
#include <getopt.h>
#include <jansson.h>
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

typedef struct {
    char* data;
    unsigned long int pos;
} buffer;

size_t get_response_data( char *ptr, size_t size, size_t nmemb, void *_buf )
{
    buffer *buf = (buffer*)_buf;
    memcpy( buf->data + buf->pos, ptr, size * nmemb );
    buf->pos += size * nmemb;
    return size * nmemb;
}

int main( const int argc, char* const* argv )
{

    int err;
    bdgr_badge badge;
    CURL* const handle = curl_easy_init();
    char* rpc_server = "http://127.0.0.1:8336";
    char* rpc_creds, * rpc_user, * rpc_pass = NULL, * badge_json;
    char* badge_id, * post_data, * response;
    const char* const id_prefix = "nmc://";
    const unsigned long int id_prefix_len = strlen( id_prefix );
    const char* const rpc_fmt = "{\"method\":\"name_show\",\"params\":[\"%s\"]}";
    const unsigned long int rpc_fmt_len = strlen( rpc_fmt ) - 2;
    unsigned long int rpc_user_len, rpc_pass_len;
    struct curl_slist *headers = 0;
    buffer buf;
    json_t* root, * result, * value, * pubkey, * value_root;
    json_error_t error;
    bdgr_key key;
    int verified;
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
        exit( 2 );
    }
    if( optind < argc ) {
        badge_json = argv[ optind++ ];
    } else {
        usage();
        exit( 2 );
    }

    err = bdgr_badge_import( badge_json, &badge );
    if( err ) {
        fprintf( stderr, "badge import error\n" );
        exit( err );
    }

    if( strncmp( badge.id, id_prefix, id_prefix_len ) ) {
        fprintf( stderr, "id must start with \"%s\"\n", id_prefix );
        exit( 2 );
    }
    badge_id = badge.id + id_prefix_len;

    if( rpc_pass == NULL ) {
        rpc_pass = getpass( "Enter namecoind rpc password: " );
        rpc_pass_len = strlen( rpc_pass );
    }
    rpc_creds = malloc( rpc_user_len + rpc_pass_len + 2 );
    sprintf( rpc_creds, "%s:%s", rpc_user, rpc_pass );

    headers = curl_slist_append( headers, "Content-Type: text/plain" );
    curl_easy_setopt( handle, CURLOPT_HTTPHEADER, headers );

    post_data = malloc( rpc_fmt_len + strlen( badge_id ));
    sprintf( post_data, rpc_fmt, badge_id );
    
    curl_easy_setopt( handle, CURLOPT_POSTFIELDS, post_data );

    curl_easy_setopt( handle, CURLOPT_USERPWD, rpc_creds );
    
    curl_easy_setopt( handle, CURLOPT_URL, rpc_server );

    buf.data = malloc( 2048 );
    buf.pos = 0;
    curl_easy_setopt( handle, CURLOPT_WRITEFUNCTION, get_response_data );
    curl_easy_setopt( handle, CURLOPT_WRITEDATA, &buf );

    curl_easy_perform( handle );

    response = malloc( buf.pos+1 );
    memcpy( response, buf.data, buf.pos );
    response[ buf.pos ] = '\0';
    
    root = json_loads( response, 0, &error );
    if( !root ) {
        fprintf( stderr, "json error: on line %d: %s\n", error.line, error.text );
        exit( 2 );
    }

    result = json_object_get( root, "result" );
    if( json_is_null( result )) {
        fprintf( stderr, "%s\n", response );
        exit( 2 );
    }

    value = json_object_get( result, "value" );
    if( !json_is_string( value )) {
        fprintf( stderr, "invalid json data\n" );
        exit( 2 );
    }

    value_root = json_loads( json_string_value( value ), 0, &error );
    if( !value_root ) {
        fprintf( stderr, "json error: on line %d: %s\n", error.line, error.text );
        exit( 2 );
    }

    pubkey = json_object_get( value_root, "pubkey" );
    if( !json_is_string( pubkey )) {
        fprintf( stderr, "invalid json data: no pubkey attribute\n" );
        exit( 2 );
    }

    err = bdgr_key_decode( json_string_value( pubkey ), &key );
    if( err ) {
        fprintf( stderr, "error decoding pubkey\n" );
        exit( err );
    }

    err = bdgr_badge_verify( &badge, &key, &verified );
    if( err ) {
        fprintf( stderr, "error verifying badge\n" );
        exit( err );
    }

    if( verified ) {
        fprintf( stderr, "Verified" );
    } else {
        fprintf( stderr, "Not verified" );
        exit( 1 );
    }
    
    return 0;
    
}
