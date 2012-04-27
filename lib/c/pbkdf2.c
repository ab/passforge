/*
** SYNOPSIS
**   echo "passphrase" | pbkdf2 salt_hex count > 48_byte_hex_key_and_iv
**
** DESCRIPTION
**
** Make the "Password-Based Key Derivation Function v2" function found in
** the openssl library available to the command line, as it is not available
** for use from the "openssl" command.  At the time of writing the "openssl"
** command only encrypts using the older, 'fast' pbkdf1.5 method.
**
** The 'salt_hex' is the salt to be used, as a hexadecimal string. Typically
** this is 8 bytes (64 bit), and is an assigned randomly during encryption.
**
** The 'count' is iteration count used to make the calculation of the key
** from the passphrase longer so as to take 1/2 to 2 seconds to generate.
** This complexity prevents slows down brute force attacks enormously.
**
** The output of the above is a 48 bytes in hexadeximal, which is typically
** used for 32 byte encryption key KEY and a 16 byte IV as needed by
** Crypt-AES-256 (or some other encryption method).
**
** NOTE: While the "openssl" command can accept a hex encoded 'key' and 'iv'
** it only does so on the command line, which is insecure.  As such I
** recommend that the output only be used with API access to the "OpenSSL"
** cryptography libraries.
**
** FUTURE: Provide an optional argument to specify the Key+IV output size
** wanted.  As given above it currently defaults to 48 bytes (32 key + 16 iv).
**
*************
**
** Anthony Thyssen   4 November 2009      A.Thyssen@griffith.edu.au
**
** Program based on a test program "pkcs5.c" found on
**   http://www.mail-archive.com/openssl-users@openssl.org
** which uses openssl to perform PBKDF2 (RFC2898) iteritive (slow) password
** hashing.
**
** Build
**    gcc -o pbkdf2 pbkdf2.c -lssl
**
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

void print_hex(unsigned char *buf, int len)
{
  int i;

  for (i=0; i<len; i++) {
    printf("%02x",(unsigned int) buf[i]);
  }
  printf("\n");
}

void hex_to_binary(unsigned char *buf, char *hex)
{
  // TODO: rewrite
  for( ; sscanf( hex, "%2x", buf++ ) == 1 ; hex+=2 );
  *buf = 0;  // null terminate -- precaution
}

int main(int argc, char **argv)
{
  char pass[1024];      // passphrase read from stdin
  unsigned char salt[1024];      // salt (binary)
  int salt_len;                  // salt length in bytes
  int ic;                        // iterative count
  unsigned char result[1024];       // result (binary - 32+16 chars)

  if ( argc != 3 ) {
    fprintf(stderr, "usage: %s salt count <passwd >binary_key_iv\n", argv[0]);
    exit(10);
  }

  hex_to_binary(salt, argv[1]);
  salt_len=strlen(argv[1])/2;   /* WARNING: assume it is a evne number! */

  ic = atoi(argv[2]);

  fgets(pass, 1024, stdin);
  if ( pass[strlen(pass)-1] == '\n' )
    pass[strlen(pass)-1] = '\0';

#if DEBUG
  // PBKDF 1.5 
  // NOTE: this is used by "openssl enc" but only with a  ic value of 1
  // This make brute force dictionary attacks posible!!!!  -- Arrggghh
  EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, pass, strlen(pass),
         ic, result, result+32);
  printf("EVP_BytesToKey(\"%s\", \"%s\", %d)=\n", pass, salt, ic);
  print_hex(result, 32);     // Key   (as hex)
  print_hex(result+32, 16);  // IV   (as hex)
#endif

  // PBKDF 2
  PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), salt, salt_len, ic, 32+16, result);
  //print_hex(result, 32+16);  // Key + IV   (as hex)
#if DEBUG
  printf("PKCS5_PBKDF2_HMAC_SHA1(\"%s\", \"%s\", %d)=\n", pass, salt, ic);
  print_hex(result, 32);               // Key   (as hex)
  print_hex(result+32, 16);            // IV   (as hex)
  //fwrite(result, 1, 32+16, stdout);  // Key + IV (as binary)
#else
  print_hex(result, 32+16);            // Key + IV   (as hex string)
#endif

  return(0);
}
