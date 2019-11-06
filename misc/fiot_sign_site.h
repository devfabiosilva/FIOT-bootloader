/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// This tool generates a signed trusted site based in trust of chain. Sites is signed using one of 3 MASTER KEYS


#define MAGIC_SZ 16
#define URL_SZ 256
#define SIGNED_SITE_MAJOR_VERSION (int)1
#define SIGNED_SITE_MINOR_VERSION (int)1
static const char MAGIC[MAGIC_SZ] = {'_','f','i','o','t','s','i','g','n','e','d','s','i','t','e','_'};
typedef struct signed_site_t {
   uint8_t magic[MAGIC_SZ];
   uint32_t version;
   uint32_t port1;
   uint8_t url1[URL_SZ];
   uint32_t port2;
   uint8_t url2[URL_SZ];
   uint32_t port3;
   uint8_t url3[URL_SZ];
   uint8_t signature[64];
} __attribute__ ( (packed) ) SIGNED_SITE;

_Static_assert(sizeof(SIGNED_SITE)==864, "SIGNED_SITE should be 864 bytes long!");

