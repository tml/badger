#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <tomcrypt.h>
#include <getopt.h>
#include <badger.h>

void usage()
{
    printf(
        "Usage: badger_badge id base64_token\n"
        "Options:\n"
        "-p, --pass  password OR\n"
        "-k, --key   base64_private_key\n"
    );
}

int main( const int argc, char* const* argv )
{

    int err;
    bdgr_key key;
    bdgr_badge badge;
    char* pass = NULL, * key_string = NULL, * id, * token, * badge_string = NULL;
    unsigned long int token_len, tokenb_len, signature_len = 2048;
    unsigned char* tokenb, * signature = malloc( signature_len );
    int c;
    
    while (1) {
        static struct option long_options[] = {
            { "pass", required_argument, 0, 'p' },
            { "key",  required_argument, 0, 'k' },
            { 0, 0, 0, 0 }
        };
        int option_index = 0;
        c = getopt_long( argc, argv, "p:k:", long_options, &option_index);
        if (c == -1)
            break;
        switch(c) {
        case 'p':
            pass = optarg;
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
    if( optind < argc ) {
        id = argv[ optind++ ];
    } else {
        usage();
        exit( 1 );
    }
    if( optind < argc ) {
        token = argv[ optind++ ];
        token_len = strlen( token );
    } else {
        usage();
        exit( 1 );
    }
    if( optind != argc ) {
        usage();
        exit( 1 );
    }

    if( pass == NULL && key_string == NULL ) {
        usage();
        exit( 1 );
    }

    if( pass != NULL ) {
        err = bdgr_key_generate( pass, &key );
        if( err ) {
            puts( "error generating key" );
            exit( err );
        }
    } else {
        err = bdgr_key_decode( key_string, &key );
        if( err ) {
            puts( "error decoding key" );
            exit( err );
        }
    }

    tokenb_len = token_len;
    tokenb = malloc( tokenb_len );
    err = base64_decode( (unsigned char*)token, token_len, tokenb, &tokenb_len );
    if( err ) {
        puts( "error decoding token" );
        exit( err );
    }

    err = bdgr_token_sign( tokenb, tokenb_len, &key, signature, &signature_len );
    if( err ) {
        puts( "error signing token" );
        exit( err );
    }

    err = bdgr_badge_make( id, tokenb, tokenb_len, signature, signature_len, &badge );
    if( err ) {
        puts( "error making badge" );
        exit( err );
    }
    
    err = bdgr_badge_export( &badge, &badge_string );
    if( err ) {
        puts( "error exporting badge" );
        exit( err );
    }

    puts( badge_string );
    
    return 0;
    
}
