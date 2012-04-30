/*
 * Passforge
 *
 * Copyright 2012 Andy brody
 *
 * Released under the GNU Public License, version 2.0 or greater.
 */

#define _XOPEN_SOURCE 500

#include <err.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define DEBUG 0

void print_hex(unsigned char *buf, int len) {
    for (int i=0; i<len; i++) {
        printf("%02x",(unsigned int) buf[i]);
    }
    printf("\n");
}

/* use OpenSSL routines to encode in base64 */
char *base64_encode(unsigned char *bytes, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, bytes, length);
    (void)BIO_flush(b64); // cast to suppress compiler warning
    BIO_get_mem_ptr(b64, &bptr);

    char *buf = malloc(bptr->length);
    if (!buf) {
        return NULL;
    }

    memcpy(buf, bptr->data, bptr->length - 1);
    buf[bptr->length - 1] = 0;

    BIO_free_all(b64);

    return buf;
}

/* Password-Based Key Derivation Function, version 2 */
int pbkdf2(char *pass, size_t pass_len, unsigned char *salt, size_t salt_len,
           int iterations, const EVP_MD *digest, int bytes,
           unsigned char *result) {
    if (!pass) {
        fprintf(stderr, "no passphrase given\n");
        return 2;
    }
    if (!salt) {
        fprintf(stderr, "no salt given\n");
        return 3;
    }
    if (!result) {
        fprintf(stderr, "no result pointer given\n");
        return 4;
    }
    if (!digest) {
        fprintf(stderr, "no HMAC function given\n");
        return 5;
    }
    if (iterations <= 0) {
        fprintf(stderr, "iterations must be > 0\n");
        return 6;
    }

    if (PKCS5_PBKDF2_HMAC(pass, pass_len, salt, salt_len, iterations, digest,
                          bytes, result)) {
        /* success */
        return 0;
    } else {
        return 1;
    }
}

int pbkdf2_sha1(char *pass, size_t pass_len, unsigned char *salt,
                size_t salt_len, int iterations, int bytes,
                unsigned char *result) {
    OpenSSL_add_all_algorithms();
    const EVP_MD *md = EVP_sha1();
    return pbkdf2(pass, pass_len, salt, salt_len, iterations, md, bytes,
                  result);
}

int pbkdf2_sha256(char *pass, size_t pass_len, unsigned char *salt,
                  size_t salt_len, int iterations, int bytes,
                  unsigned char *result) {
    OpenSSL_add_all_algorithms();
    const EVP_MD *md = EVP_sha256();
    return pbkdf2(pass, pass_len, salt, salt_len, iterations, md, bytes,
                  result);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr,
                "usage: %s [options] nickname iterations [length]\n",
                argv[0]);
        exit(1);
    }

    unsigned char *salt = (unsigned char *) argv[1];
    int salt_len = strlen(argv[1]);

    int ic = atoi(argv[2]);
    if (ic <= 0) {
        fprintf(stderr, "error: iterations must be > 0\n");
        exit(7);
    }

    int length = 16;
    if (argc > 3) {
        length = atoi(argv[3]);
        if (length <= 0) {
            fprintf(stderr, "error: length must be > 0\n");
            exit(8);
        }
    }

    int bytes = (int) ceil((double)length * 3 / 4);
    if (bytes <= 0) {
        fprintf(stderr, "error: would have derived %d bytes\n", bytes);
        exit(12);
    }

    unsigned char *dKey = malloc(bytes);
    if (!dKey) {
        err(9, "failed to allocate memory for result");
    }

    char *passbuf = getpass("master password: ");
    if (!passbuf) {
        err(10, "getpass");
    }
    char *pass = strdup(passbuf);
    if (!pass) {
        err(11, "strdup");
    }

    int passlen = strlen(pass);
    int res = pbkdf2_sha1(pass, passlen, salt, salt_len, ic, bytes, dKey);
    if (res) {
        fprintf(stderr, "ERROR\n");
        return res;
    }

    int as_hex = 0;
    if (as_hex) {
        /* print as hex */
        print_hex(dKey, bytes);
    } else {
#if DEBUG
        print_hex(dKey, bytes);
#endif
        char *output = base64_encode(dKey, bytes);
        if (!output) {
            err(13, "failed to get output buffer");
        }

        /* truncate to length */
        if (strlen(output) > length) {
            output[length] = '\0';
        }

#if DEBUG
        print_hex((unsigned char *)output, length);
#endif

        printf("%s\n", output);
    }

    return(0);
}

/* vim: set ts=4 sw=4 et tw=79 */
