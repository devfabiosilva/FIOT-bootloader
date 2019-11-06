/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// timer routines to implement in FIOT certificate file format


//Seg 08 Jul 2019 18:20:53 -03

#define _XOPEN_SOURCE
#include <string.h>
#include <time.h>

int is_common_year(unsigned int year)
{
/*
// 0 is leap year
// 1 is common year
*/
//if (year%4)
   if (year&0x3) return 1;
   else if (year%100) return 0;
   else if (year%400) return 1;
   else return 0;
}

int valid_date(int day, int month, int year)
{
	int k_day=0;
/*
 FIXME please debug it. I am analyzing the behavior of passing year. I'm not sure if the algorithm below is correct.
 if you find a bug, please correct and send me a message at fabioegel@gmail.com.
 Code from MY EMBEDDED SYSTEM 8-bit adapted (2014).
*/
// Sakamoto's formula is valid only 30/09/1752 and above

//printf("\nDEBUG funcao \"valid_date\"\n");
//printf("Dia %d, Mes %d, Ano %d\n", day, month, year);
   if ((year > 1752)&&(month>0))
   {
      if (month < 8) {
         if (month==2) {
            if (is_common_year(year)) k_day = 28;
            else k_day=29;
         } else if (month&0x01) k_day=31;
         else k_day=30;
      } else if (month < 13) {
         if (month&0x01) k_day=30;
         else k_day=31;
      }
   }

   if (day <= k_day) return day;
   else return 0;
}

int f_get_time_str(char *str_date, struct tm *tm)
{
   int err=1;
   char *p;
   char strfmt[20];

   p=strchr(str_date, 'T');

   if (p) {
      *p = ' ';
      strcpy(strfmt, "%Y-%m-%d  %H:%M:%S");
   } else
      strcpy(strfmt, "%Y-%m-%d");

   if (strptime(str_date, strfmt, tm)==NULL) {
      //printf("\nErro ocorrido\n");
      return err;
   }

   if (valid_date(tm->tm_mday, tm->tm_mon+1, tm->tm_year+1900)) {
      err=0;
      tm->tm_isdst=-1;
   }

   return err;
}
