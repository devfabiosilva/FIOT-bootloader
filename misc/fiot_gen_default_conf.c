/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// This tool generates a raw default value to stored in FIOT bootloader secure boot encrypted region. Every hard reset, bootloader parses these
// default value to FIOT encrypted partition to be accessed by user program


//Sáb 20 Jul 2019 23:36:44 -03
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "fiot_sign_site.h"
#include "f_mbedtls_util.h"
#include "fiot_gen_default_conf.h"


#define MAJOR_VER (uint32_t)1
#define MINOR_VER (uint32_t)1

#define FIOT_USAGE "\nUsage \"%s\" \n"
#define FIOT_NAME "fiot_gen_default -of <FILENAME> -uid <FILENAME_UID> -priv_rsa_file <FILE_PRIV_RSA> -pk <EXPORTED_MASTER_PK>"
#define FIOT_MSG "\n(C) 2019 - FIOT GENERATE DEFAULT DATA TOOL\n\n" \
                      "Fábio Pereira da Silva\n\n"\
                      "Ver.: %d.%d\n" \
                      FIOT_USAGE\
                      "\n\n\n"

int main(int argc, char **argv)
{
   int err;
   int i;
   size_t rsa_file_sz;
   char *of=NULL;
   char *uid=NULL;
   char *priv_rsa_file=NULL;
   char *pk=NULL;

   char buf[1024];

   F_PUBLIC_KEY master_pk[NUM_MPK];

   F_PARTITION_BLOCK block;

   FILE *of_f, *uid_f, *priv_rsa_file_f, *pk_f;

   if (argc==1) {
      printf(FIOT_MSG, MAJOR_VER, MINOR_VER, FIOT_NAME);
      return 0;
   }

   if (argc>9) {
      printf("\nError. Too many arguments\n\n");
      return 1;
   }

   for (i=1;i<argc;i++) {
      if (strcmp(argv[i], "-of")==0) {
         if (argc==++i) {
            printf("\n\nMissing output filename\n\n");
            return 1;
         } else
            of=argv[i];
      } else if (strcmp(argv[i], "-uid")==0) {
         if (argc==++i) {
            printf("\n\nMissing uid filename\n\n");
            return 1;
         } else
            uid=argv[i];
      } else if (strcmp(argv[i], "-priv_rsa_file")==0) {
         if (argc==++i) {
            printf("\n\nMissing private RSA file\n\n");
            return 1;
         } else
            priv_rsa_file=argv[i];
      } else if (strcmp(argv[i], "-pk")==0) {
         if (argc==++i) {
            printf("\n\nMissing exported master public key file\n\n");
            return 1;
         } else
            pk=argv[i];
      } else {
         printf("\nMissing argument\n"FIOT_USAGE, FIOT_NAME);
         return 1;
      }
   }

   if (!of) {
      printf("\nOutput file missing\n");
      return 1;
   }

   if (!uid) {
      printf("\nUID file missing\n");
      return 1;
   }

   if (!priv_rsa_file) {
      printf("\nPrivate RSA file missing\n");
      return 1;
   }

   if (!pk) {
      printf("\nMaster public key missing\n");
      return 1;
   }

   err=1;

   uid_f=fopen(uid, "r");

   printf("\n\nOpening uid file \"%s\" ...", uid);

   if (!uid_f) {
      printf(FAIL);
      printf("\nError. Can't open file \"%s\"\n", uid);
      return 1;
   }

   printf(OK);

   memset(&block, 0, sizeof(block));

   printf("\nReading file \"%s\" ...", uid);

   if (fread(block.header.fiot_unique_id, 1, sizeof(FIOT_UID), uid_f)^sizeof(FIOT_UID)) {
      printf(FAIL);
      printf("\Error.\nError on reading file \"%s\".\n", uid);
      goto main_EXIT1;
   }

   printf(OK);

   fhex2str(block.header.fiot_unique_id, sizeof(block.header.fiot_unique_id), buf);

   printf("\nVerifying valid uid \"%s\" ...", buf);

   memcpy(buf+sizeof(buf)-sizeof(FIOT_UID), block.header.fiot_unique_id, sizeof(FIOT_UID));

   if (get_uid((FIOT_UID *)(buf+sizeof(buf)-sizeof(FIOT_UID)))) {
      printf(FAIL);
      printf("\nInvalid uid \"%s\"\nAbort.\n", buf);
      goto main_EXIT1;
   }

   printf(OK);

   printf("\nValidating RSA file \"%s\" ...", priv_rsa_file);

   err=verify_valid_rsa_private_key_file(priv_rsa_file);

   if (err) {
      printf(FAIL);
      printf("\nINVALID RSA FILE \"%d\"\n", err);
      goto main_EXIT1;
   }

   printf(OK);

   err=1;

   printf("\nOpening private RSA file \"%s\" ...", priv_rsa_file);

   priv_rsa_file_f=fopen(priv_rsa_file, "r");

   if (!priv_rsa_file_f) {
      printf(FAIL);
      printf("\nError. Can't open file \"%s\"\n", priv_rsa_file);
      goto main_EXIT1;
   }

   printf(OK);

   printf("\nChecking file size of file \"%s\"...", priv_rsa_file);

   err=f_get_file_size(priv_rsa_file_f, (long int *)&rsa_file_sz);

   if (err) {
      printf(FAIL);
      printf("\nError when checking file size \"%s\"\n", priv_rsa_file);
      goto main_EXIT2;
   }

   err=1;

   if (rsa_file_sz>F_PRIV_KEY_CERT_SZ) {
      printf(FAIL);
      printf("\nError. File size is %lu bytes. It must be less or equal to %lu bytes.\n", (long int)rsa_file_sz, (long int)F_PRIV_KEY_CERT_SZ);
      goto main_EXIT2;
   }

   printf(OK);

   block.priv_cert_file.len=(uint32_t)rsa_file_sz;

   if (fread(block.priv_cert_file.priv_key_cert, 1, rsa_file_sz, priv_rsa_file_f)^rsa_file_sz) {
      printf(FAIL);
      printf("\nCould not read \"%s\" file. Exiting ...\n", priv_rsa_file);
      goto main_EXIT2;
   }

   printf(OK);

   printf("\nOpening master public key file \"%s\" ...", pk);

   pk_f=fopen(pk, "r");

   if (!pk_f) {
      printf(FAIL);
      printf("\nError.\nCan't open file \"%s\".\nAbort\n", pk);
      goto main_EXIT2;
   }

   printf(OK);

   printf("\nReading master public key file \"%s\" ...", pk);

   if (fread(master_pk, 1, sizeof(master_pk), pk_f)^sizeof(master_pk)) {
      printf(FAIL);
      printf("\nError when opening file \"%s\" to verify signed site.\nAbort\n", pk);
      goto main_EXIT3;
   }

   printf(OK);

//   err=1;

   printf("\nFormating block:\n\tHead ...");

   memcpy(block.header.magic, PARTITION_MAGIC_FACTORY, sizeof(block.header.magic));
   memcpy(block.header.part_desc, PART_DESCRIPTION, sizeof(PART_DESCRIPTION));
   memcpy(block.header.pk, master_pk, sizeof(master_pk));

   printf(OK);

   printf("\n\tUpdate info ...");

   block.ota_update_info.ota_mode=F_OTA_FACTORY;
   block.ota_update_info.firmware_version=FIRMWARE_VERSION;
   block.ota_update_info.factory_firmware_version=FACTORY_FIRMWARE_VERSION;
   block.ota_update_info.bootloader_version=BOOTLOADER_VERSION;
   block.ota_update_info.timestamp=(uint64_t)time(NULL);

   printf(OK);

   printf("\n\tUpdate info CRC ...");

   block.ota_update_info.crc32=f_crc32((char *)&block.ota_update_info+sizeof(uint32_t), sizeof(block.ota_update_info)-sizeof(uint32_t));

   printf(OK);

   printf("\n\tGenerating default SoftAP config and CRC ...");

   block.soft_ap_cfg.cfg=INITIALIZE_SOFT_AP;
   f_str_cpy_safe(block.soft_ap_cfg.ssid, F_SOFT_AP_DEFAULT_NAME, F_MAX_SSID_LEN_V2);
   f_str_cpy_safe(block.soft_ap_cfg.passwd, F_SOFT_AP_DEFAULT_PASSWORD, F_MAX_PASSWORD_LEN_V2);
   block.soft_ap_cfg.crc32=f_crc32((char *)&block.soft_ap_cfg+sizeof(uint32_t), sizeof(block.soft_ap_cfg)-sizeof(uint32_t));

   printf(OK);

   printf("\n\tSoftAP login page CRC ...");

   f_str_cpy_safe(block.soft_ap_login_page.ssid, F_LOGIN_PAGE_USER, F_MAX_SSID_LEN_V2);
   f_str_cpy_safe(block.soft_ap_login_page.passwd, F_LOGIN_PAGE_PASSWORD, F_MAX_SSID_LEN_V2);
   block.soft_ap_login_page.crc32=f_crc32((char *)&block.soft_ap_login_page+sizeof(uint32_t), sizeof(block.soft_ap_login_page)-sizeof(uint32_t));

   printf(OK);

   printf("\n\tWifi config CRC ...");

   block.wifi_cfg.crc32=f_crc32((char *)&block.wifi_cfg+sizeof(uint32_t), sizeof(block.wifi_cfg)-sizeof(uint32_t));

   printf(OK);
   
// Note crc32 of cloud_file_private_key is not generated by default. On first error 
//TRNG and FIOT functions will generate an arbitrary iv and private keys on first error

   printf("\n\tVerify private RSA key CRC ...");

   block.priv_cert_file.crc32=f_crc32((char *)&block.priv_cert_file+sizeof(uint32_t), sizeof(block.priv_cert_file)-sizeof(uint32_t));

   printf(OK);

   printf("\n\tVerifying cleaned trusted keys CRC ...");

   block.trusted_key.crc32=f_crc32((char *)&block.trusted_key+sizeof(uint32_t), sizeof(block.trusted_key)-sizeof(uint32_t));

   printf(OK);

   printf("\n\tVerifying MBEDTLS_ECP_DP_NONE cleaned self key pair CRC ...");

   block.self_key_pair.key_pair_type=MBEDTLS_ECP_DP_NONE;

   block.self_key_pair.crc32=f_crc32((char *)&block.self_key_pair+sizeof(uint32_t), sizeof(block.self_key_pair)-sizeof(uint32_t));

   printf(OK);

   printf("\n\tGenerating SHA256 integrity block ...");

   memcpy(block.header.data_integrity,
         //f_sha256_digest((void *)(&block.header), sizeof(block)-sizeof(block.header)), //<-Fixed @ Seg 22 Jul 2019 21:45:18 by fabiolinux
         f_sha256_digest((void *)&block+sizeof(block.header), sizeof(block)-sizeof(block.header)),
         sizeof(block.header.data_integrity));

   printf(OK);

   printf("\nCreating file \"%s\" ...", of);

   of_f=fopen(of, "w");

   if (!of_f) {
      printf(FAIL);
      printf("\nError. Can't create output file \"%s\".\nAbort.\n\n", of);
      goto main_EXIT3;
   }

   printf(OK);

   printf("\nWriting created block in file \"%s\" ...", of);

   if (fwrite(&block, 1, sizeof(block), of_f)^sizeof(block)) {
      printf(FAIL);
      printf("\nCan't write block of size %d bytes in \"%s\".\nAbort\n\n", (int)sizeof(block), of);
      goto main_EXIT4;
   }

   err=0;
   printf("\nEXIT SUCCESS !!!\n\n");
main_EXIT4:
   fclose(of_f);
main_EXIT3:
   fclose(pk_f);
main_EXIT2:
   fclose(priv_rsa_file_f);
main_EXIT1:
   fclose(uid_f);

   return err;
}
