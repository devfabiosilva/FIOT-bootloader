/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// This tool verifies a signed trusted site based in trust of chain. Sites is signed using one of 3 MASTER KEYS


//Dom 14 Jul 2019 14:56:01 -03
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "mbedtls/error.h"
#include "mbedtls/platform.h"

#include "fiot_sign_site.h"
#include "f_mbedtls_util.h"

#define MAJOR_VER (uint32_t)1
#define MINOR_VER (uint32_t)1

#define FIOT_USAGE "\nUsage \"%s\" \n"
#define FIOT_NAME "fiot_verify_signed_site <FILENAME> <MASTER_PUBLIC_KEY (optional)>"
#define FIOT_MSG "\n(C) 2019 - FIOT VERIFY SIGNED SITE TOOL\n\n" \
                      "Fábio Pereira da Silva\n\n"\
                      "Ver.: %d.%d\n" \
                      FIOT_USAGE\
                      "\n\n\n"

static char buf[1024];

void show_details(SIGNED_SITE *signed_site)
{
   printf("\n\n============FIOT SIGNED SITE DETAILS=============\n\n");
   printf("\nVersion: %d.%d\n\n", ((signed_site->version)>>16), ((signed_site->version)&0x0000FFFF));

   if (strnlen(signed_site->url1, URL_SZ-1)) {
      if (signed_site->port1)
         printf("\nURI port 1: %d\n", (int)signed_site->port1);
      printf("\nURI 1: %s\n", signed_site->url1);
   }

   if (strnlen(signed_site->url2, URL_SZ-1)) {
      if (signed_site->port2)
         printf("\nURI port 2: %d\n", (int)signed_site->port2);
      printf("\nURI 2: %s\n", signed_site->url2);
   }

   if (strnlen(signed_site->url3, URL_SZ-1)) {
      if (signed_site->port3)
         printf("\nURI port 3: %d\n", (int)signed_site->port3);
      printf("\nURI 3: %s\n", signed_site->url3);
   }

   fhex2str(signed_site->signature, 64, buf);
   printf("\n\nSignature: %s\n\n", buf);

   printf("\n\n=========END FIOT SIGNED SITE DETAILS============\n\n");
}


int main(int argc, char **argv)
{
   int err;

   FILE *f, f_pk;
   SIGNED_SITE signed_site;
   mbedtls_pk_context pub_sign_key;
   char pk[MBEDTLS_ECDSA_MAX_LEN];

   if (argc==1) {
      printf(FIOT_MSG, MAJOR_VER, MINOR_VER, FIOT_NAME);
      return 0;
   }

   if (argc>3) {
      printf("\nError. Too many arguments\n\n");
      return 1;
   }

   f=fopen(argv[1], "r");

   if (!f) {
      printf("\nFile not found \"%s\"\n", argv[1]);
      return 1;
   }

   if (fread(&signed_site, 1, sizeof(signed_site), f)^sizeof(signed_site)) {
      printf("\nError when reading signed site file.\nIs this \"%s\" an Fiot Signed Sites?\n\nAborting\n", argv[1]);
      goto main_EXIT1;
   }

   if (memcmp(signed_site.magic, MAGIC, sizeof(MAGIC))) {
       printf("\nError\n\nInvalid Signed Site file\n\n");
       goto main_EXIT1;
   }

   show_details(&signed_site);

   if (argc==3) {

      mbedtls_pk_init(&pub_sign_key);
      err=mbedtls_pk_parse_public_keyfile(&pub_sign_key, argv[2]);

      printf("\nOpening file \"%s\" ...", argv[2]);

      if (err) {
         printf(FAIL);
         mbedtls_pk_free(&pub_sign_key);
         mbedtls_strerror(err, (char *)buf, sizeof(buf));
         mbedtls_printf("Error opening file. Is this public PEM file?\n ! mbedtls_pk_parse_public_keyfile returned -0x%04x - %s\n\n", -err, buf);
         return err;
      }

      printf(OK);

      printf("\nVerifying public key type ...");

      if (mbedtls_pk_get_type(&pub_sign_key)!=MBEDTLS_PK_ECKEY) {
         printf(FAIL);
         mbedtls_pk_free(&pub_sign_key);
         printf("\nError: File (master public key) \"%s\" is not an ECKEY\n", argv[2]);
         return 1;
      }

      printf(OK);

      printf("\nVerifying curve SECP256v1 ...");

      if ((mbedtls_pk_ec(pub_sign_key)->grp.id)!=MBEDTLS_ECP_DP_SECP256R1) {
         printf(FAIL);
         mbedtls_pk_free(&pub_sign_key);
         printf("\nError. Fiot bootloader works only with signed SECP256v1 curve\n");
         return 1;
      }

      printf(OK);

      printf("\nExtracting public key file in \"%s\" file...", argv[2]);

      err=f_extract_public_key(mbedtls_pk_ec(pub_sign_key), pk);

      if (err==0) {
         printf(FAIL);
         mbedtls_pk_free(&pub_sign_key);
         printf("\nError on extracting public key in \"%s\" file\n", argv[2]);
         return 1;
      }

      fhex2str(pk, err, buf);

      printf(OK);

      printf("\nChecking Fiot SIGNED SITE with public key: %s...", buf);

      err=f_verify_ecdsa_v2(MBEDTLS_ECP_DP_SECP256R1, pk, (void *)&signed_site, sizeof(signed_site)-64, signed_site.signature);

      if (err) {
         printf(FAIL);
         mbedtls_pk_free(&pub_sign_key);
         printf("\nERROR. Signature NOT PASS !!! File may be corrupt or wrong master public key\n\n");
         return err;
      }
      printf("\nVerify OK !!!\n\n");
      mbedtls_pk_free(&pub_sign_key);
   }

main_EXIT1:
   fclose(f);
   return err;
}
