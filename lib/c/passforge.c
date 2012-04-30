/*
 * Passforge
 *
 * Copyright 2012 Andy brody
 *
 * Released under the GNU Public License, version 2.0 or greater.
 */

#define _XOPEN_SOURCE 500

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

void print_hex(unsigned char *buf, int len) {
    printf("0x");
    for (int i=0; i<len; i++) {
        printf("%02x",(unsigned int) buf[i]);
    }
    printf("\n");
}

int pbkdf2(char *pass, size_t pass_len, unsigned char *salt, size_t salt_len,
           int iterations, const EVP_MD *digest, int bytes, unsigned char *result) {
    if (!pass) {
        return 2;
    }
    if (!salt) {
        return 3;
    }
    if (!result) {
        return 4;
    }
    if (!digest) {
        return 5;
    }
    if (iterations <= 0) {
        return 6;
    }

    if (PKCS5_PBKDF2_HMAC(pass, pass_len, salt, salt_len, iterations, digest, bytes, result)) {
        /* success */
        return 0;
    } else {
        return 1;
    }
}

int pbkdf2_sha1(char *pass, size_t pass_len, unsigned char *salt, size_t salt_len,
                int iterations, int bytes, unsigned char *result) {
    OpenSSL_add_all_algorithms();
    const EVP_MD *md = EVP_sha1();
    return pbkdf2(pass, pass_len, salt, salt_len, iterations, md, bytes, result);
}

int pbkdf2_sha256(char *pass, size_t pass_len, unsigned char *salt, size_t salt_len,
                  int iterations, int bytes, unsigned char *result) {
    OpenSSL_add_all_algorithms();
    const EVP_MD *md = EVP_sha256();
    return pbkdf2(pass, pass_len, salt, salt_len, iterations, md, bytes, result);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr,
                "usage: %s [options] nickname iterations [length]\n",
                argv[0]);
        exit(1);
    }

    unsigned char *salt = (unsigned char *) argv[1];
    int salt_len = strlen(argv[1]);

    int ic = atoi(argv[2]);

    char *passbuf = getpass("master password: ");
    if (!passbuf) {
        err(2, "getpass");
    }
    char *pass = strdup(passbuf);
    if (!pass) {
        err(3, "strdup");
    }

    int length = 32;
    unsigned char *result = malloc(length);
    if (!result) {
        err(4, "failed to allocate memory for result");
    }

    int res = pbkdf2_sha1(pass, strlen(pass), salt, salt_len, ic, length, result);
    if (res) {
        return res;
    }

    int as_hex = 0;
    if (as_hex) {
        print_hex(result, length);
    } else {
        BIO *bio, *b64;
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_fp(stdout, BIO_NOCLOSE);
        bio = BIO_push(b64, bio);
        BIO_write(bio, result, length);
        (void) BIO_flush(bio); // cast to avoid compiler warning
        BIO_free_all(bio);
    }

    return(0);
}
