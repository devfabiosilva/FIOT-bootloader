/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// This tool generates a FIOT UID (Unique ID) through a random number generator


//Dom 14 Jul 2019 17:06:30 -03
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#include "f_mbedtls_util.h"
#include "f_time.h"

#define MAJOR_VER (uint32_t)1
#define MINOR_VER (uint32_t)1

#define FIOT_USAGE "\nUsage \"%s\" -d <date(optional> -n <production_number(optional)> -of <file(optional)>\n"
#define FIOT_NAME "fiot_gen_uid"
#define FIOT_MSG "\n(C) 2019 - FIOT GENERATE UID TOOL\n\n" \
                      "Fábio Pereira da Silva\n\n"\
                      "Ver.: %d.%d\n" \
                      FIOT_USAGE\
                      "\n\n\n"

//TIMESTAMP(8)|LN(4)|RAND(4)|CRC(4)
//static const char *peer="7.!xK{Ts%~]zQkJlA(1=+)2@?|c>:cbE,\"#xfGw}/]0I^M";

int main(int argc, char **argv)
{
   int err;
   FIOT_UID uid;
   char *d=NULL;
   char *n=NULL;
   char *of=NULL;
   FILE *f=NULL;
   struct tm tm;
   long int k;
   int i;

   if (argc==1) {
      printf(FIOT_MSG, MAJOR_VER, MINOR_VER, FIOT_NAME);
      return 0;
   }

   for (i=1;i<argc;i++) {
      if (strcmp(argv[i], "-d")==0) {
         if (argc==++i) {
            printf("\nMissing date. It must be YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD\n");
            return 1;
         } else
            d=argv[i];
      } else if (strcmp(argv[i], "-n")==0) {
         if (argc==++i) {
            printf("\nMissing number of production\n");
            return 1;
         } else
            n=argv[i];
      } else if (strcmp(argv[i], "-of")==0) {
         if (argc==++i) {
            printf("\nMissing output filename\n");
            return 1;
         } else
            of=argv[i];
      } else {
         printf("\nMissing argument\n"FIOT_USAGE, FIOT_NAME);
         return 1;
      }
   }

   printf("\nBegin generating id ...");
   memset(&uid, 0, sizeof(uid));

   if (d) {
      memset(&tm, 0, sizeof(tm));
      printf("\nValidating input date %s ...", d);
      if (f_get_time_str(d, &tm)) {
         printf(FAIL);
         printf("\nInvalid date. Input date must be YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD.\n\nAbort...\n");
         return 1;
      }

      printf(OK);
      
      printf("\nSaving date to uid...");

      uid.timestamp=(uint64_t)mktime(&tm);

   } else {
      uid.timestamp=(uint64_t)time(NULL);
      printf("\nSetting current date and time \"%s\" ...", ctime((time_t *)&uid.timestamp));
   }

   if ((time_t)uid.timestamp==(time_t)-1) {
      printf(FAIL);
      printf("\nError. \"mktime\"\n");
      return 1;
   }

   printf(OK);

   if (n) {
      printf("\nSetting number o production \"%s\" ...", n);

      if (err=f_str_to_long(n, 10, &k)) {
         printf(FAIL);
         printf("\nError in \"f_str_to_long\" %d\n. Abort...\n", err);
         return 1;
      }

      if (k&0xFFFFFFFFFFFF0000) {
         printf(FAIL);
         printf("\nValue out of range of uint16_t.\nAborting ...\n");
         return 1;
      }
      uid.production_no=(uint32_t)k;
      printf(OK);
   }

   printf("\nGenerating uid. It can take a while. Improve entropy moving mouse, open programs, press keys ...\nand wait ...");

   if (generate_uid(&uid)) {
      printf(FAIL);
      printf("\nError when generating uid.\n Abort...\n");
      return 1;
   }

   printf(OK);

   if (show_uid_info(&uid))
      return 1;

   if (of) {

      printf("\nCreating file %s ...", of);

      f=fopen(of, "w");

      if (!f) {
         printf(FAIL);
         printf("\nCan't create file %s\nAborting ...\n", of);
         return 1;
      }

      printf(OK);
      printf("\nWriting file hex value to file \"%s\" ...", of);
      err=0;

      if (fwrite(&uid,1,sizeof(uid),f)^sizeof(uid)) {
         err=1;
         printf(FAIL);
         printf("\nError when writing file \"%s\".\nAbort", of);
      } else
         printf(OK);

      printf("\n\n");

      fclose(f);

      return err;

   }

   return 0;
}
