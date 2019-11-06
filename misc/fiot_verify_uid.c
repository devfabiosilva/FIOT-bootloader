/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// This tool verifies a generated string|binary UID


//Ter 16 Jul 2019 00:57:59 -03
#include <stdio.h>
#include <string.h>

#include "f_mbedtls_util.h"


#define MAJOR_VER (uint32_t)1
#define MINOR_VER (uint32_t)1

#define FIOT_USAGE "\nUsage \"%s\" -s|-f <uid_string>|<uid_file>\n"
#define FIOT_NAME "fiot_verify_uid"
#define FIOT_MSG "\n(C) 2019 - FIOT VERIFY UID TOOL\n\n" \
                      "Fábio Pereira da Silva\n\n"\
                      "Ver.: %d.%d\n" \
                      FIOT_USAGE\
                      "\n\n\n"

int main(int argc, char **argv)
{
   char *string=NULL;
   char *filename=NULL;
   int i;
   int err;
   FIOT_UID uid;
   FILE *f;

   if (argc==1) {
      printf(FIOT_MSG, MAJOR_VER, MINOR_VER, FIOT_NAME);
      return 0;
   }

   if (argc>3) {
      printf("\nToo many arguments\n");
      return 1;
   }

   for (i=1;i<argc;i++) {
      if (strcmp(argv[i], "-s")==0) {
         if (argc==++i) {
            printf("\nMissing string. It must 40 hex value\n");
            return 1;
         } else
            string=argv[i];
      } else if (strcmp(argv[i], "-f")==0) {
         if (argc==++i) {
            printf("\nMissing filename\n");
            return 1;
         } else
            filename=argv[i];
      } else {
         printf("\nMissing argument\n"FIOT_USAGE, FIOT_NAME);
         return 1;
      }
   }

   if (string) {
      printf("\nReading string \"%s\" ...", string);
      if (err=f_strtouid(string, &uid)) {
         printf(FAIL);
         if (err^60) {
            printf("\nInvalid chars. Only hex characters are allowed\n");
            return 1;
         }
         printf("\nYou must specify UID with 40 hex characters\n");
         return 1;
      }
      printf(OK);
      goto main_EXIT;
   }

   if (filename) {
      printf("\nOpening file \"%s\" ...", filename);
      f=fopen(filename, "r");
      if (!f) {
         printf(FAIL);
         printf("\nError opening file \"%s\".\n\n", filename);
         return 1;
      }
      printf(OK);
      printf("\nReading \"%s\" ...", filename);
      if (fread(&uid,1,sizeof(uid),f)^sizeof(uid)) {
         printf(FAIL);
         printf("\nError reading file \"%s\".\n\n", filename);
         fclose(f);
         return 1;
      }
      fclose(f);
      printf(OK);
   }

main_EXIT:
   if (err=show_uid_info(&uid))
      printf("\nError in \"show_uid_info\" %d\n\nInvalid uid\n\n", err);

   return err;
}
