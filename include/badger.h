/* Copyright (c) 2013 John Driscoll */

#ifndef BADGER_H
#define BADGER_H

typedef struct {
    unsigned char*    name;
    unsigned long int name_len;
    unsigned char*    token;
    unsigned long int token_len;
    unsigned char*    signature;
    unsigned long int signature_len;
} bdgr_badge;

typedef dsa_key bdgr_key;

int bdgr_generate_key(
    const unsigned char* pass,
    const unsigned long int pass_len,
    bdgr_key* key );

int bdgr_import_key(
    const unsigned char* data,
    const unsigned long int data_len,
    bdgr_key* key );

void bdgr_free_key(
    bdgr_key* key );

int bdgr_sign_token(
    const unsigned char* token,
    const unsigned long int token_len,
    const bdgr_key* key,
    unsigned char* signature,
    unsgined long int* signature_len );

const bdgr_badge bdgr_make_badge(
    const unsigned char* name,
    const unsigned long int name_len,
    const unsigned char* token,
    const unsigned long int token_len,
    const unsigned char* signature,
    const unsgined long int* signature_len );

int bdgr_verify_badge(
    const bdgr_badge* badge,
    const bdgr_key* key,
    int* verified );

int bdgr_import_badge(
    const unsigned char* data,
    const long unsigned int data_len,
    bdgr_badge* badge );

int bdgr_export_badge(
    const bdgr_badge* badge,
    unsigned char* data,
    unsigned long int data_len );

#endif
