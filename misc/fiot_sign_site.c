/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// This tool generates a signed trusted site based in trust of chain. Sites is signed using one of 3 MASTER KEYS


//Sáb 13 Jul 2019 00:37:27 -03
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "mbedtls/error.h"
#include "mbedtls/platform.h"

#include "fiot_sign_site.h"
#include "f_mbedtls_util.h"

#define MAJOR_VER (uint32_t)1
#define MINOR_VER (uint32_t)1

#define FIOT_USAGE "\nUsage \"%s\" -url1 <site1> -p1 <port1 (optional)> -url2 <site2> -p2 <port2 (optional)> -url3 <site3> -p3 <port3 (optional)> -of <file> -mk <private_master_key_file>\n"
#define FIOT_NAME "fiot_sign_site"
#define FIOT_MSG "\n(C) 2019 - FIOT SIGN SITE TOOL\n\n" \
                      "Fábio Pereira da Silva\n\n"\
                      "Ver.: %d.%d\n" \
                      FIOT_USAGE\
                      "\n\n\n"

#define MSG_MISSING_SITE_NAME "\nError: Site %s must be specified\n"

int main(int argc, char **argv)
{
   int i;
   int err;

   char buf[1024];
   char *mk=NULL;
   char *url[3]={NULL};
   char *port[3]={NULL};
   char *filename=NULL;
   char *ptr_url[3];
   char *master_priv_key_file_name=NULL;
   SIGNED_SITE signed_site;
   uint32_t *port_val[3];
   long int k;
   FILE *f;

   mbedtls_pk_context priv_master_key;

   char private_key[MBEDTLS_ECDSA_MAX_LEN];

   if (argc==1) {
      printf(FIOT_MSG, MAJOR_VER, MINOR_VER, FIOT_NAME);
      return 0;
   }

   for (i=1;i<argc;i++) {
      if (strcmp(argv[i], "-url1")==0) {
         if (argc==++i) {
            printf(MSG_MISSING_SITE_NAME, "1");
            return 1;
         } else
            url[0]=argv[i];
      } else if (strcmp(argv[i], "-url2")==0) {
         if (argc==++i) {
            printf(MSG_MISSING_SITE_NAME, "2");
            return 1;
         } else
            url[1]=argv[i];
      } else if (strcmp(argv[i], "-url3")==0) {
         if (argc==++i) {
            printf(MSG_MISSING_SITE_NAME, "3");
            return 1;
         } else
            url[2]=argv[i];
      } else if (strcmp(argv[i], "-of")==0) {
         if (argc==++i) {
            printf("\nMissing output file\n");
            return 1;
         } else
            filename=argv[i];
      } else if (strcmp(argv[i], "-mk")==0) {
         if (argc==++i) {
            printf("\nMissing master private key file\n");
            return 1;
         } else
            mk=argv[i];
      } else if (strcmp(argv[i], "-p1")==0) {
         if (argc==++i) {
            printf("\nMissing port number\n");
            return 1;
         } else
            port[0]=argv[i];
      } else if (strcmp(argv[i], "-p2")==0) {
         if (argc==++i) {
            printf("\nMissing port number\n");
            return 1;
         } else
            port[1]=argv[i];
      } else if (strcmp(argv[i], "-p3")==0) {
         if (argc==++i) {
            printf("\nMissing port number\n");
            return 1;
         } else
            port[2]=argv[i];
      } else {
         printf("\nMissing argument\n"FIOT_USAGE, FIOT_NAME);
         return 1;
      }
   }

   err=0;

   if (url[0]) err++;
   if (url[1]) err++;
   if (url[2]) err++;

   if (err==0) {
      printf("\nError: At least one site pointer must be specified.\n");
      return 1;
   }

   if (!filename) {
      printf("\nError: You must specify a output filename\n");
      return 1;
   }

   if (!mk) {
      printf("\nError. You must specify a master key *.pem file\n");
      return 1;
   }

   printf("\nBuilding header ...");

   memset(&signed_site, 0, sizeof(SIGNED_SITE));

   memcpy(signed_site.magic, MAGIC, sizeof(MAGIC));

   signed_site.version=((SIGNED_SITE_MAJOR_VERSION<<16)|SIGNED_SITE_MINOR_VERSION);

   printf(OK);

   ptr_url[0]=signed_site.url1;
   ptr_url[1]=signed_site.url2;
   ptr_url[2]=signed_site.url3;

   port_val[0]=&signed_site.port1;
   port_val[1]=&signed_site.port2;
   port_val[2]=&signed_site.port3;

   for (i=0;i<3;i++)
      if (url[i]) {
         printf("\nAdding url%d \"%s\" ...", i+1, url[i]);
         strncpy(ptr_url[i], url[i], URL_SZ-1);
         printf(OK);
         if (port[i]) {
            printf("\nAssign port %d value...", i+1);
            err=f_str_to_long(port[i], 10, &k);

            if (err) {
               printf(FAIL);
               printf("\nError: Invalid port %d number %d\n", i+1, err);
               return 1;
            }

            if (((uint64_t)k)&((uint64_t)0xFFFFFFFF00000000)) {
               printf(FAIL);
               printf("\nError: Integer too long in port %d\n", i+1);
               return 1;
            }
            *port_val[i]=(uint32_t)k;
            printf("%s %s",port[i], OK);
            //printf(OK);
         }
      }// else printf("\nURL %d == NULL\n",i);

   printf("\nInitializing sign algorithm ...");

   mbedtls_pk_init(&priv_master_key);

   printf(OK);

   printf("\nOpening private master key \"%s\" file...", mk);

   err = mbedtls_pk_parse_keyfile(&priv_master_key, mk, NULL);

   if (err) {
      printf(FAIL);
      mbedtls_strerror(err, (char *)buf, sizeof(buf));
      mbedtls_printf("\nError opening file. Is this private PEM file?\n ! mbedtls_pk_parse_keyfile returned -0x%04x - %s\n\n", -err, buf);
      goto main_EXIT1;
   }

   printf(OK);

   err=1;

   printf("\nVerifying master private key algorithm type ...");

   if (mbedtls_pk_get_type(&priv_master_key)!=MBEDTLS_PK_ECKEY) {
      printf(FAIL);
      printf("\nError: File (master private key) \"%s\" is not an ECKEY\n", mk);
      goto main_EXIT1;
   }

   printf(OK);

   printf("\nVerifying master private key curve type ...");

   if ((mbedtls_pk_ec(priv_master_key)->grp.id)!=MBEDTLS_ECP_DP_SECP256R1) {
      printf(FAIL);
      printf("\nError. Fiot bootloader works only with signed SECP256v1 curve\n");
      goto main_EXIT1;
   }

   printf(OK);

   printf("\nExtracting private key from \"%s\" file...", mk);

   err = f_extract_private_key(mbedtls_pk_ec(priv_master_key), private_key);

   if (err==0) {
      err=1;
      printf(FAIL);
      printf("\nError on extracting private key to assign Fiot uri's\n");
      goto main_EXIT2;
   }

   printf(OK);

   printf("\nSigning file block with master private key in \"%s\" file.\nThis can take a little longer. How about opening programs and move mouse, press keys to increase entropy?\nGenerating random numbers and signing... wait ...", mk);

   err=f_sign_ecdsa_v2(MBEDTLS_ECP_DP_SECP256R1, private_key, (void *)&signed_site, sizeof(signed_site)-64, signed_site.signature);

   if (err==0) {
      err=1;
      printf(FAIL);
      printf("\nError. Could not assign certificate to save in \"%s\" file.\n", filename);
      goto main_EXIT2;
   }

   err=1;

   printf(OK);

   printf("\nCreating file \"%s\"...", filename);

   f=fopen(filename, "w");

   if (!f) {
      printf(FAIL);
      printf("\nError. Can't create file \"%s\". Aborting...\n", filename);
      goto main_EXIT2;
   }

   printf(OK);

   printf("\nWriting signed block to \"%s\" file ...", filename);

   if (fwrite(&signed_site,1,sizeof(signed_site),f)^sizeof(signed_site)) {
      printf(FAIL);
      printf("\nError when writing Fiot uri site to \"%s\" file.\n", filename);
      goto main_EXIT3;
   }

   err=0;
   printf(OK);

main_EXIT3:
   fclose(f);
main_EXIT2:
   memset(private_key, 0, sizeof(private_key));
main_EXIT1:
   mbedtls_pk_free(&priv_master_key);
   memset(&priv_master_key, 0, sizeof(priv_master_key));

   (err)?(printf("\nErrors found\n\n")):(printf("\nSuccess!!\n\n"));

   return err;
}
