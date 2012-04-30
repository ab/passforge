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
#include <stdbool.h>
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

/* Use OpenSSL routines to encode in base64. */
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
    const EVP_MD *md = EVP_sha1();
    return pbkdf2(pass, pass_len, salt, salt_len, iterations, md, bytes,
                  result);
}

int pbkdf2_sha256(char *pass, size_t pass_len, unsigned char *salt,
                  size_t salt_len, int iterations, int bytes,
                  unsigned char *result) {
    const EVP_MD *md = EVP_sha256();
    return pbkdf2(pass, pass_len, salt, salt_len, iterations, md, bytes,
                  result);
}

char *passforge(char *pass, size_t pass_len, unsigned char *salt,
                size_t salt_len, int iterations, int length,
                double *elapsed_seconds, bool use_sha256) {

    time_t start, end;
    if (elapsed_seconds) {
        start = time(NULL);
        *elapsed_seconds = 0;
    }

    int bytes = (int) ceil((double)length * 3 / 4);
    if (bytes <= 0) {
        fprintf(stderr, "error: cannot derive %d bytes\n", bytes);
        return NULL;
    }

    unsigned char *dKey = malloc(bytes);
    if (!dKey) {
        fprintf(stderr, "error: failed to allocate memory for result\n");
        return NULL;
    }

    int res;
    if (use_sha256) {
        res = pbkdf2_sha256(pass, pass_len, salt, salt_len, iterations, bytes,
                            dKey);
    } else {
        res = pbkdf2_sha1(pass, pass_len, salt, salt_len, iterations, bytes,
                          dKey);
    }
    if (res) {
        fprintf(stderr, "error: pbkdf2 failed\n");
        return NULL;
    }

    char *output = base64_encode(dKey, bytes);
    if (!output) {
        fprintf(stderr, "error: failed to base64 encode result\n");
        return NULL;
    }

#if DEBUG
    print_hex(dKey, bytes);
#endif

    // truncate to length
    if (strlen(output) > length) {
        output[length] = '\0';
    }

    if (elapsed_seconds) {
        end = time(NULL);
        *elapsed_seconds = difftime(end, start);
    }

    return output;
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

    char *passbuf = getpass("master password: ");
    if (!passbuf) {
        err(10, "getpass");
    }
    char *pass = strdup(passbuf);
    if (!pass) {
        err(11, "strdup");
    }

    bool use_sha256 = true;

    int passlen = strlen(pass);
    double elapsed = 0;
    char *output = passforge(pass, passlen, salt, salt_len, ic, length,
                             &elapsed, use_sha256);

    printf("%s\n", output);
    return(0);
}

/* vim: set ts=4 sw=4 et tw=79: */
