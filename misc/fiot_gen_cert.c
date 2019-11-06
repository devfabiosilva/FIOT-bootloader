/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// This tool generates a certificate based in chain of trust of MASTER key stored in FIOT bootloader in secure boot area.


//Qua 03 Jul 2019 22:01:13 -03
//#Qui 04 Jul 2019 14:43:26 -03

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

#define FIOT_USAGE "\nUsage \"%s\" -mk MASTER_PRIVATE_KEY.pem -pk NON_MASTER_PUBLIC_KEY.pem -ed EXPIRE_DATE(optional) -m MESSAGE(optional) -of FILE.fcf\n"
#define FIOT_NAME "fiot_gen_cert"
#define FIOT_MSG "\n(C) 2019 - FIOT CERTIFICATE TOOL GENERATOR\n\n" \
                      "Fábio Pereira da Silva\n\n"\
                      "Ver.: %d.%d\n" \
                      FIOT_USAGE\
                      "\n\n\n"

int main(int argc, char **argv)
{
   char *mk=NULL;
   char *pk=NULL;
   char *ed=NULL;
   char *msg=NULL;
   char *of=NULL;

   FILE *f_of;
   char buf[1024];
   int i;
   int err;

   time_t expire_date;
   struct tm tm;

   FIOT_CERTIFICATE cert;

   mbedtls_pk_context priv_master_key;
   mbedtls_pk_context pub_cert_key;

   char private_key[MBEDTLS_ECDSA_MAX_LEN];

   if (argc==1) {
      printf(FIOT_MSG, MAJOR_VER, MINOR_VER, FIOT_NAME);
      return 0;
   }

   for (i=1;i<argc;i++) {
      if (strcmp(argv[i], "-mk")==0) {
         if (argc==++i) {
            printf("\nMissing master key file\n");
            return 1;
         } else
            mk=argv[i];
      } else if (strcmp(argv[i], "-pk")==0) {
         if (argc==++i) {
            printf("\nMissing private key file\n");
            return 1;
         } else
            pk=argv[i];
      } else if (strcmp(argv[i], "-ed")==0) {
         if (argc==++i) {
            printf("\nMissing expire date\n");
            return 1;
         } else
            ed=argv[i];
      } else if (strcmp(argv[i], "-m")==0) {
         if (argc==++i) {
            printf("\nMissing message\n");
            return 1;
         } else
            msg=argv[i];
      } else if (strcmp(argv[i], "-of")==0) {
         if (argc==++i) {
            printf("\nMissing output file\n");
            return 1;
         } else
            of=argv[i];
      } else {
         printf("\nMissing argument\n"FIOT_USAGE, FIOT_NAME);
         return 1;
      }
   }

   if (mk==NULL) {
      printf("\nMissing. Master key is needed\n");
      return 1;
   }

   if (pk==NULL) {
      printf("\nError. Missing certificate. Public key is needed\n");
      return 1;
   }

   if (of==NULL) {
      printf("\nError. Output file is missing\n");
      return 1;
   }

   if (ed) {
      memset(&tm, 0, sizeof(struct tm));

      if (f_get_time_str(ed, &tm)) {
         printf("\nError. Invalid expire date.\n");
         return 1;
      }

      expire_date=mktime(&tm);

      if (expire_date==(time_t)-1) {
         printf("\nError. \"mktime\"\n");
         return 1;
      }
   }

   f_of=fopen(of, "w");

   if (!f_of) {
      printf("\nError. Can't create \"%s\"!", of);
      return 1;
   }

   mbedtls_pk_init(&priv_master_key);
   mbedtls_pk_init(&pub_cert_key);

   err = mbedtls_pk_parse_keyfile(&priv_master_key, mk, NULL);

   if (err) {
      mbedtls_strerror(err, (char *)buf, sizeof(buf));
      mbedtls_printf("Error opening file. Is this private PEM file?\n ! mbedtls_pk_parse_keyfile returned -0x%04x - %s\n\n", -err, buf);
      goto main_EXIT1;
   }

   err=1;

   if (mbedtls_pk_get_type(&priv_master_key)!=MBEDTLS_PK_ECKEY) {
      printf("\nError: File (master private key) \"%s\" is not an ECKEY\n", mk);
      goto main_EXIT1;
   }

   if ((mbedtls_pk_ec(priv_master_key)->grp.id)!=MBEDTLS_ECP_DP_SECP256R1) {
      printf("\nError. FIOT bootloader works only with signed SECP256v1 curve\n");
      goto main_EXIT2;
   }

   err=mbedtls_pk_parse_public_keyfile(&pub_cert_key, pk);

   if (err) {
      mbedtls_strerror(err, (char *) buf, sizeof(buf));
      mbedtls_printf( "Error opening file. Is this public PEM file?\n ! mbedtls_pk_parse_public_keyfile returned -0x%04x - %s\n\n", -err, buf );
      goto main_EXIT2;
   }

   if (mbedtls_pk_get_type(&pub_cert_key)!=MBEDTLS_PK_ECKEY) {
      err=1;
      printf("\nError: File (public key) \"%s\" is not an ECKEY\n", pk);
      goto main_EXIT3;
   }

   memset(&cert, 0, sizeof(FIOT_CERTIFICATE));

   err=f_extract_public_key(mbedtls_pk_ec(pub_cert_key), cert.pkey);

   if (err==0) {
      err=1;
      printf("\nError on extracting public key in \"%s\" file\n", pk);
      goto main_EXIT3;
   }

   cert.pkey_type=(uint32_t)mbedtls_pk_ec(pub_cert_key)->grp.id;

   memcpy(cert.magic, CERTIFICATE_MAGIC, sizeof(CERTIFICATE_MAGIC));

   if (msg)
      strncpy(cert.certificate_description, msg, CERTIFICATE_DESCRIPTION_SZ-1);
   else
      strcpy(cert.certificate_description, CERTIFICATE_DESCRIPTION);

   cert.create_At=(uint64_t)time(NULL);

   if (ed)
      if (cert.create_At>(cert.expire_At=(uint64_t)expire_date)) {
         err=1;
         printf("\nError. Expired date cannot be less than %s\n", ctime(&cert.create_At));
         goto main_EXIT3;
      }

   cert.version=(uint32_t)((MAJOR_VER<<16)|MINOR_VER);

   err = f_extract_private_key(mbedtls_pk_ec(priv_master_key), private_key);

   if (err==0) {
      err=1;
      printf("\nError on extracting private key to assign Fiot Certificate\n");
      goto main_EXIT4;
   }

   err=f_sign_ecdsa_v2(MBEDTLS_ECP_DP_SECP256R1, private_key, (void *)&cert, sizeof(cert)-64, cert.signature);

   if (err==0) {
      err=1;
      printf("\nError. Could not assign certificate to save in \"%s\" file.\n", of);
      goto main_EXIT4;
   }

   if (fwrite(&cert,1,sizeof(cert),f_of)^sizeof(cert)) {
      err=1;
      printf("\nError when writing Fiot Certificate to \"%s\" file.\n", of);
      goto main_EXIT4;
   }

   err=0;

   printf("\nFiot Certificate File \"%s\" created successfully\n", of);

main_EXIT4:
   memset(private_key, 0, sizeof(private_key));
main_EXIT3:
   mbedtls_pk_free(&pub_cert_key);
   memset(&pub_cert_key, 0, sizeof(pub_cert_key));
main_EXIT2:
   mbedtls_pk_free(&priv_master_key);
   memset(&priv_master_key, 0, sizeof(priv_master_key));
main_EXIT1:
   fclose(f_of);
   return err;
}

