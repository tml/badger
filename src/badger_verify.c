#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <curl/curl.h>
#include <getopt.h>
#include <jansson.h>
#include <badger.h>

void usage()
{
    printf(
        "Usage: badger_verify badge\n"
        "Options:\n"
        "-r, --rpc   http://user[:pass]@rpc_server_address:port\n"
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
    char* rpc_server = NULL, * badge_json, * badge_id, * post_data, * response;
    const char* const id_scheme = "bdgr://";
    const unsigned long int id_scheme_len = strlen( id_scheme );
    const char* const rpc_fmt = "{\"method\":\"name_show\",\"params\":[\"bdgr/%s\"]}";
    const unsigned long int rpc_fmt_len = strlen( rpc_fmt ) - 2;
    struct curl_slist *headers = 0;
    buffer buf;
    json_t* root, * result, * value, * pubkey, * value_root;
    json_error_t error;
    bdgr_key key;
    int verified;
    int c;
    
    while (1) {
        static struct option long_options[] = {
            { "server",  required_argument, 0, 's' },
            { 0, 0, 0, 0 }
        };
        int option_index = 0;
        c = getopt_long( argc, argv, "s:", long_options, &option_index);
        if( c == -1 )
            break;
        switch( c ) {
        case 's':
            rpc_server = optarg;
            break;
        case '?':
            break;
        default:
            abort();
        }
    }
    if( optind < argc ) {
        badge_json = argv[ optind++ ];
    } else {
        usage();
        exit( 1 );
    }

    if( rpc_server == NULL ) {
        struct passwd* pw = getpwuid( getuid() );
        char* rel_path = "/.namecoin/bitcoin.conf";
        char* conf_path = malloc( strlen( pw->pw_dir ) + strlen( rel_path ) + 1);
        char name[80], val[256], * line = NULL, * pos;
        char* rpc_scheme = "http://";
        char* rpcport = "8336", * rpcconnect = "127.0.0.1";
        char* rpcuser = NULL, * rpcpass = NULL;
        size_t len;
        FILE* conf;
        sprintf( conf_path, "%s%s", pw->pw_dir, rel_path );
        conf = fopen( conf_path, "r" );
        if( conf != NULL ) {
            while( getline( &line, &len, conf ) != -1) {
                pos = strstr( line, "=" );
                if( pos == NULL ) {
                    continue;
                }
                strncpy( name, line, pos - line );
                name[ pos - line ] = '\0';
                strncpy( val, pos + 1, strlen( line ) - ((pos + 1) - line) - 1 );
                val[ strlen( line ) - ((pos + 1) - line) - 1 ] = '\0';
                if( !strcmp( "rpcport", name ) ) {
                    rpcport = malloc( strlen( val ) + 1 );
                    strcpy( rpcport, val );
                } else if ( !strcmp( "rpcconnect", name ) ) {
                    rpcconnect = malloc( strlen( val ) + 1 );
                    strcpy( rpcconnect, val );
                } else if ( !strcmp( "rpcuser", name ) ) {
                    rpcuser = malloc( strlen( val ) + 1 );
                    strcpy( rpcuser, val );
                } else if ( !strcmp( "rpcpassword", name ) ) {
                    rpcpass = malloc( strlen( val ) + 1 );
                    strcpy( rpcpass, val );
                }
            }
        }
        if( rpcuser == NULL ) {
            rpc_server = malloc(
                strlen( rpc_scheme ) + strlen( rpcconnect ) + 1 + strlen( rpcport ) + 1 );
            sprintf( rpc_server, "%s%s:%s",
                     rpc_scheme, rpcconnect, rpcport );
        } else if( rpcpass == NULL ) {
            rpc_server = malloc(
                strlen( rpc_scheme ) + strlen( rpcuser ) + 1 +
                strlen( rpcconnect ) + 1 + strlen( rpcport ) + 1 );
            sprintf( rpc_server, "%s%s@%s:%s",
                     rpc_scheme, rpcuser, rpcconnect, rpcport );
        } else {
            rpc_server = malloc(
                strlen( rpc_scheme ) + strlen( rpcuser ) + 1 + strlen( rpcpass ) + 1 +
                strlen( rpcconnect ) + 1 + strlen( rpcport ) + 1 );
            sprintf( rpc_server, "%s%s:%s@%s:%s",
                     rpc_scheme, rpcuser, rpcpass, rpcconnect, rpcport );
        }
    }

    err = bdgr_badge_import( badge_json, &badge );
    if( err ) {
        fprintf( stderr, "badge import error\n" );
        exit( err );
    }

    if( strncmp( badge.id, id_scheme, id_scheme_len ) ) {
        fprintf( stderr, "id must start with \"%s\"\n", id_scheme );
        exit( 2 );
    }
    badge_id = badge.id + id_scheme_len;

    headers = curl_slist_append( headers, "Content-Type: text/plain" );
    curl_easy_setopt( handle, CURLOPT_HTTPHEADER, headers );

    post_data = malloc( rpc_fmt_len + strlen( badge_id ));
    sprintf( post_data, rpc_fmt, badge_id );
    
    curl_easy_setopt( handle, CURLOPT_POSTFIELDS, post_data );

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
