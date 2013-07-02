#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <jansson.h>
#include <badger.h>

void usage()
{
    printf(
        "Usage: badger_key\n"
        "Options:\n"
        "-p, --pass  password\n"
        "-k, --key   base64_public_key\n"
    );
}

int main( const int argc, char* const* argv )
{
    int err;
    json_t* root;
    char* pass = NULL, * key_string = NULL, * string = NULL;
    unsigned long int pass_len;
    bdgr_key key;
    int c;
    
    while (1) {
        static struct option long_options[] = {
            { "pass", required_argument, 0, 'p' },
            { "key",  required_argument, 0, 'k' },
            { 0, 0, 0, 0 }
        };
        int option_index = 0;
        c = getopt_long( argc, argv, "p:", long_options, &option_index);
        if (c == -1)
            break;
        switch(c) {
        case 'p':
            pass = optarg;
            pass_len = strlen( pass );
            break;
        case 'k':
            key_string = optarg;
            break;
        case '?':
            break;
        default:
            abort();
        }
    }

    if( key_string == NULL ) {
        
        if( pass == NULL && key_string == NULL ) {
            pass = getpass( "Enter password: " );
            pass_len = strlen( pass );
        }
        
        if( !pass_len ) {
            usage();
            exit( 1 );
        }
        
        err = bdgr_key_generate( pass, &key );
        if( err ) {
            puts( "error generating key" );
            exit( err );
        }
        
        err = bdgr_key_encode_private( &key, &key_string );
        if( err ) {
            puts( "error encoding key" );
            exit( err );
        }
        
    }

    root = json_pack(
        "{ss}",
        "pubkey", key_string );
    if( !root ) {
        puts( "error packing json" );
        exit( 1 );
    }

    string = json_dumps( root, 0 );
    if( !string ) {
        puts( "error dumping json" );
        exit( 2 );
    }
    
    puts( string );
    printf("%d\n", strlen( string ));
    
    return 0;
    
}
