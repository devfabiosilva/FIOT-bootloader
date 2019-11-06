/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// This tool verifies a signed certificate in trust of chain. Sites is signed using one of 3 MASTER KEYS


//Seg 08 Jul 2019 23:43:55 -03 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"

#include "f_mbedtls_util.h"
#include "f_time.h"

#define MAJOR_VER (uint32_t)1
#define MINOR_VER (uint32_t)1

#define FIOT_USAGE "\nUsage \"%s\" <FILENAME> <MASTER_PUBLIC_KEY (OPTIONAL)>\n"
#define FIOT_NAME "fiot_verify_cert"
#define FIOT_MSG "\n(C) 2019 - FIOT VERIFY CERTIFICATE TOOL\n\n" \
                      "Fábio Pereira da Silva\n\n"\
                      "Ver.: %d.%d\n" \
                      FIOT_USAGE\
                      "\n\n\n"


static const char *F_CURVES_NAME[] = {
                                        "MBEDTLS_ECP_DP_NONE","MBEDTLS_ECP_DP_SECP192R1","MBEDTLS_ECP_DP_SECP224R1", "MBEDTLS_ECP_DP_SECP256R1",
                                        "MBEDTLS_ECP_DP_SECP384R1", "MBEDTLS_ECP_DP_SECP521R1","MBEDTLS_ECP_DP_BP256R1", "MBEDTLS_ECP_DP_BP384R1",
                                        "MBEDTLS_ECP_DP_BP512R1", "MBEDTLS_ECP_DP_CURVE25519", "MBEDTLS_ECP_DP_SECP192K1", "MBEDTLS_ECP_DP_SECP224K1",
                                        "MBEDTLS_ECP_DP_SECP256K1", "MBEDTLS_ECP_DP_CURVE448"
                                     };
#define F_CURVES_NAME_SZ (int)14

void show_details(FIOT_CERTIFICATE *cert)
{
   size_t sz;
   char buf[2*MBEDTLS_ECDSA_MAX_LEN+1];
   mbedtls_ecdsa_context ecdsa_context;
   int err;

   mbedtls_ecdsa_init(&ecdsa_context);

   err=mbedtls_ecp_group_load(&ecdsa_context.grp, cert->pkey_type);

   if (err) {
      printf("\nError when group load function \"mbedtls_ecp_group_load\"\n");
      goto show_details_EXIT;
   }

   sz=2*mbedtls_mpi_size(&ecdsa_context.grp.P);

   fhex2str(cert->pkey, sz, buf);
   printf("\n\n============FIOT CERTIFICATE DETAILS============\n\n");
   printf("\nVersion: %d.%d\n\n", ((cert->version)>>16), ((cert->version)&0x0000FFFF));
   printf("\nCertificate Public Key: %s\n", buf);
   printf("\nCertificate description: %s\n", cert->certificate_description);
   printf("\nCertificate Public Key Size: %d\n", (int)sz);
   printf("\nPublic Key Algorithm Name: %s\n", ((cert->pkey_type)>=F_CURVES_NAME_SZ)?"Unknown type":F_CURVES_NAME[cert->pkey_type]);
   printf("\nCreated: %s\n", ctime(&cert->create_At));
   (cert->expire_At)?(printf("\nExpire in: %s\n", ctime(&cert->expire_At))):(printf("\nNever expires\n"));
   fhex2str(cert->signature, 64, buf);
   printf("\nCertificate signature: %s\n\n", buf);
   printf("\n\n===========END FIOT CERTIFICATE DETAILS==========\n\n");
show_details_EXIT:
   mbedtls_ecdsa_free(&ecdsa_context);
}

int main(int argc, char **argv)
{
   int err=1;
   FILE *cert_file;
   FIOT_CERTIFICATE cert;
   mbedtls_pk_context pub_sign_key;
   char buf[1024];
   char pk[MBEDTLS_ECDSA_MAX_LEN];

   if (argc==1) {
      printf(FIOT_MSG, MAJOR_VER, MINOR_VER, FIOT_NAME);
      return 0;
   }

   if (argc>3) {
      printf("\n\nError: Too many arguments\n\n");
      return 1;
   }

   cert_file=fopen(argv[1], "r");

   if (!cert_file) {
      printf("\nERROR:\n\nCan't open \"%s\" Fiot Certificate File.\n", argv[1]);
      return 1;
   }

   if (fread(&cert, 1, sizeof(FIOT_CERTIFICATE), cert_file)^sizeof(FIOT_CERTIFICATE)) {
      printf("\nError when reading certificate file.\nIs this \"%s\" an Fiot Certificate File?\n\nAborting\n", argv[1]);
      goto main_EXIT1;
   }

   if (memcmp(cert.magic, CERTIFICATE_MAGIC, sizeof(CERTIFICATE_MAGIC))) {
       printf("\nError\n\nInvalid Fiot Certificate\n\n");
       goto main_EXIT1;
   }

   show_details(&cert);

   if (argc==3) {
      mbedtls_pk_init(&pub_sign_key);
      err=mbedtls_pk_parse_public_keyfile(&pub_sign_key, argv[2]);

      printf("\nOpening file \"%s\" ...", argv[2]);

      if (err) {
         mbedtls_pk_free(&pub_sign_key);
         mbedtls_strerror(err, (char *)buf, sizeof(buf));
         mbedtls_printf("Error opening file. Is this public PEM file?\n ! mbedtls_pk_parse_public_keyfile returned -0x%04x - %s\n\n", -err, buf);
         return err;
      }

      printf(" [ ok ]");

      printf("\nVerifying public key type ...");

      if (mbedtls_pk_get_type(&pub_sign_key)!=MBEDTLS_PK_ECKEY) {
         mbedtls_pk_free(&pub_sign_key);
         printf("\nError: File (master public key) \"%s\" is not an ECKEY\n", argv[2]);
         return 1;
      }

      printf(" [ ok ]");

      printf("\nVerifying curve SECP256v1 ...");

      if ((mbedtls_pk_ec(pub_sign_key)->grp.id)!=MBEDTLS_ECP_DP_SECP256R1) {
         mbedtls_pk_free(&pub_sign_key);
         printf("\nError. Fiot bootloader works only with signed SECP256v1 curve\n");
         return 1;
      }

      printf(" [ ok ]");

      printf("\nExtracting public key file in \"%s\" file...", argv[2]);

      err=f_extract_public_key(mbedtls_pk_ec(pub_sign_key), pk);

      if (err==0) {
         mbedtls_pk_free(&pub_sign_key);
         printf("\nError on extracting public key in \"%s\" file\n", argv[2]);
         return 1;
      }

      fhex2str(pk, err, buf);

      printf(" [ ok ]");

      printf("\nChecking Fiot Certificate with public key: %s...", buf);

      err=f_verify_ecdsa_v2(MBEDTLS_ECP_DP_SECP256R1, pk, (void *)&cert, sizeof(FIOT_CERTIFICATE)-64, cert.signature);

      if (err) {
         mbedtls_pk_free(&pub_sign_key);
         printf(" [ fail ]");
         printf("\nERROR. Signature NOT PASS !!! File may be corrupt or wrong master public key\n\n");
         return err;
      }
      printf("\nVerify OK !!!\n\n");
      mbedtls_pk_free(&pub_sign_key);
   }
   printf("\nSuccess\n");
main_EXIT1:
   fclose(cert_file);
   return err;
}
