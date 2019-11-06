/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// This tool generates a raw default value to stored in FIOT bootloader secure boot encrypted region. Every hard reset, bootloader parses these
// default value to FIOT encrypted partition to be accessed by user program

//Qui 22 Ago 2019 15:08:43 -03
//All structure here is friendly with Hardware encryption access READ/WRITE (Multiple of 32 Bytes). Fabio
#include <stdint.h>

#define F_MAX_SSID_LEN_V2 76
#define F_MAX_PASSWORD_LEN_V2 F_MAX_SSID_LEN_V2
#define F_PRIV_KEY_CERT_SZ (2048+24)

#define PART_DESCRIPTION "AES-256 Encrypted partition. For bootload and firmware access. Fiot 2019. Use Bitcoin"
#define F_PART_DESCRIPTION_MAX_SZ (size_t) 144
#define PARTITION_MAGIC_FACTORY_SZ (size_t)16

#if (MBEDTLS_ECDSA_MAX_LEN&0x0000000F)
    #define F_EDSA_FILE_MAX_LEN ((MBEDTLS_ECDSA_MAX_LEN&0xFFFFFFF0) + 0x00000010)
#else
    #define F_EDSA_FILE_MAX_LEN (MBEDTLS_ECDSA_MAX_LEN)
#endif

#define F_SOFT_AP_DEFAULT_NAME "fabioIOT"
#define F_SOFT_AP_DEFAULT_PASSWORD "1234567890"

#define F_LOGIN_PAGE_USER "admin"
#define F_LOGIN_PAGE_PASSWORD F_LOGIN_PAGE_USER

static const char PARTITION_MAGIC_FACTORY[PARTITION_MAGIC_FACTORY_SZ] = {'_', 'f', 'i', 'o', 't', 'b', 'o', 'o', 't', 'l', 'o', 'a', 'd', 'e', 'r', '_'};

typedef uint8_t F_PUBLIC_KEY[64];

typedef enum f_ota_mode_enum {
    F_OTA_FACTORY=1, // Factory loads inconditionally // O bootloader carrega incondicionalmente o app de fábrica
    F_OTA_NORMAL, // bootloader loads inconditionally OTA //O bootloader carrega incondicionalmente o ota
    F_OTA_UPDATING, //bootloader will load uploader to download signed firmware // O bootloader carregará o uploader para baixar o firmware
    F_OTA_UPDATED, //bootloader attributes when ota success. User firmware set to F_OTA_NORMAL// O uploader atribui esse valor. Quando dá inicio, o bootloader carrega o firmware atualizado e set F_OTA_NORMAL
    F_OTA_UPDATING_IMAGE_INVALID_CHK_SUM,
    F_OTA_UPDATING_IMAGE_INVALID_SIG,
} f_ota_mode;

#define FIRMWARE_VERSION (uint32_t)((1<<16)|0)
#define FACTORY_FIRMWARE_VERSION (uint32_t)((1<<16)|1)
#define BOOTLOADER_VERSION FIRMWARE_VERSION

#define F_OTA_FACTORY (uint32_t)1

typedef struct f_ota_update_info_t {
    uint32_t crc32;
    uint32_t ota_mode;
    uint32_t update_id;
    uint32_t update_available;
    uint32_t firmware_version;
    uint32_t factory_firmware_version;
    uint32_t bootloader_version;
    uint32_t last_bootloader_error;
    uint8_t last_bootloader_error_reason[256];
    uint8_t reserved[16];
    uint64_t last_bootloader_error_timestamp;
    uint64_t timestamp;
} __attribute__ ( (packed) ) F_FIOT_UPDATE_INFO;

_Static_assert(sizeof(F_FIOT_UPDATE_INFO)==320, "F_FIOT_UPDATE_INFO should be 320 bytes long!");
_Static_assert((sizeof(F_FIOT_UPDATE_INFO)&0x1F)==0, "F_FIOT_UPDATE_INFO must be multiple of 32 bytes. Hardware Encryption compatible");

typedef struct f_wifi_config_v2_t {
   uint32_t crc32;
   uint32_t cfg;
   char ssid[F_MAX_SSID_LEN_V2];
   char passwd[F_MAX_PASSWORD_LEN_V2];
} __attribute__ ( (packed) ) F_WIFI_CONFIG_V2;

_Static_assert(sizeof(F_WIFI_CONFIG_V2)==(F_MAX_SSID_LEN_V2+F_MAX_PASSWORD_LEN_V2+2*sizeof(uint32_t)),"F_WIFI_CONFIG_V2: Incompatible size");
_Static_assert((sizeof(F_WIFI_CONFIG_V2)&0x1F)==0, "F_WIFI_CONFIG_V2 must be multiple of 32 bytes. Hardware Encryption compatible");

typedef struct f_ssl_private_key_t {
   uint32_t crc32;
   uint32_t len;
   uint8_t priv_key_cert[F_PRIV_KEY_CERT_SZ];
} __attribute__ ( (packed) ) F_SSL_PRIVATE_KEY;

_Static_assert(sizeof(F_SSL_PRIVATE_KEY)==(sizeof(uint32_t)*2+F_PRIV_KEY_CERT_SZ), "F_SSL_PRIVATE_KEY: Assertion failed");
_Static_assert((sizeof(F_SSL_PRIVATE_KEY)&0x1F)==0, "F_SSL_PRIVATE_KEY must be multiple of 32 bytes. Hardware Encryption compatible");

typedef struct f_file_privkey_v2_t {
    uint32_t crc32;
    uint8_t iv[16];
    uint8_t private_key[32];
    uint8_t reserved[16-sizeof(uint32_t)];
} __attribute__ ( (packed) ) F_FILE_PRIVATE_KEY_V2;

_Static_assert(sizeof(F_FILE_PRIVATE_KEY_V2)==64, "F_SSL_PRIVATE_KEY: Assertion failed. Must be 64 bytes long");
_Static_assert((sizeof(F_FILE_PRIVATE_KEY_V2)&0x1F)==0, "F_FILE_PRIVATE_KEY_V2 must be multiple of 32 bytes. Hardware Encryption compatible");

#define F_FIOT_UNIQUE_ID_SZ (size_t)20
#define F_IOT_NUM_PK (size_t)3
#define F_HEADER_RESERVED_SZ (size_t)76

typedef struct f_partition_hdr_t {
    uint8_t magic[PARTITION_MAGIC_FACTORY_SZ];
    uint8_t fiot_unique_id[F_FIOT_UNIQUE_ID_SZ];
    uint8_t reserved[F_HEADER_RESERVED_SZ];
    uint8_t part_desc[F_PART_DESCRIPTION_MAX_SZ];
    F_PUBLIC_KEY pk[F_IOT_NUM_PK];
    uint8_t data_integrity[32];
} __attribute__ ( (packed) ) F_FIOT_PARTITION_HDR;

_Static_assert(sizeof(F_FIOT_PARTITION_HDR)==480, "F_FIOT_PARTITION_HDR should be 480 bytes long");
_Static_assert((sizeof(F_FIOT_PARTITION_HDR)&0x1F)==0, "F_FIOT_PARTITION_HDR must be multiple of 32 bytes. Hardware Encryption compatible");

#define F_TRUSTED_KEY_ASSERT (size_t)24
typedef struct f_trusted_ecdsa_key_t {
   uint32_t crc32;
   uint32_t use_trusted_ecdsa_key; //0x012E4992
   uint8_t public_key[64]; // Always prime256v1!!!
   uint8_t reserved[F_TRUSTED_KEY_ASSERT];
} __attribute__( (packed) ) F_TRUSTED_KEY;

_Static_assert(sizeof(F_TRUSTED_KEY)==(2*sizeof(uint32_t)+64+F_TRUSTED_KEY_ASSERT), "F_TRUSTED_KEY size error");
_Static_assert((sizeof(F_TRUSTED_KEY)&0x1F)==0, "F_TRUSTED_KEY must be multiple of 32 bytes. Hardware Encryption compatible");

#define F_SELF_ECDSA_KEY_PAIR_ASSERT (size_t)24
typedef struct f_self_ecdsa_key_pair_t {
   uint32_t crc32;
   uint32_t key_pair_type;
   uint8_t public_key[F_EDSA_FILE_MAX_LEN];
   uint8_t private_key[F_EDSA_FILE_MAX_LEN];
   uint8_t reserved[F_SELF_ECDSA_KEY_PAIR_ASSERT];
} __attribute__ ( (packed) ) F_SELF_ECDSA_KEY_PAIR;

_Static_assert(sizeof(F_SELF_ECDSA_KEY_PAIR)==(2*sizeof(uint32_t)+2*F_EDSA_FILE_MAX_LEN+F_SELF_ECDSA_KEY_PAIR_ASSERT), "F_EDSA_FILE_MAX_LEN size error");
_Static_assert((sizeof(F_SELF_ECDSA_KEY_PAIR)&0x1F)==0, "F_SELF_ECDSA_KEY_PAIR must be multiple of 32 bytes. Hardware Encryption compatible");

typedef enum soft_ap_cfg_t {
   INITIALIZE_SOFT_AP=1,
   INITIALIZE_NORMAL
} SOFT_AP_CFG_ENUM;

typedef struct f_partition_block_t {
   F_FIOT_PARTITION_HDR header;
//   uint8_t sb[sizeof(F_FIOT_UPDATE_INFO)>>1];
   F_FIOT_UPDATE_INFO ota_update_info;
   uint8_t sc[sizeof(F_FIOT_UPDATE_INFO)>>1];
   F_WIFI_CONFIG_V2 soft_ap_cfg; // Value to keep = SoftAP or NORMAL//Aqui será guardado a opção: Iniciar em SoftAP ou iniciar em NORMAL
   F_WIFI_CONFIG_V2 soft_ap_login_page;
   F_WIFI_CONFIG_V2 wifi_cfg;
//   uint8_t se[sizeof(F_WIFI_CONFIG_V2)];
   F_FILE_PRIVATE_KEY_V2 cloud_file_private_key;
   uint8_t sf[sizeof(F_FILE_PRIVATE_KEY_V2)];
   F_SSL_PRIVATE_KEY priv_cert_file;
   F_TRUSTED_KEY trusted_key;
   F_SELF_ECDSA_KEY_PAIR self_key_pair;
} __attribute__ ( (packed) ) F_PARTITION_BLOCK;

_Static_assert(sizeof(F_PARTITION_BLOCK)<=4096, "F_PARTITION_BLOCK is greater than 4096 bytes");
_Static_assert((sizeof(F_PARTITION_BLOCK)&0x1F)==0, "F_PARTITION_BLOCK must be multiple of 32 bytes. Hardware Encryption compatible");

#define F_HEADER_SZ (size_t) sizeof(F_FIOT_PARTITION_HDR)
#define F_OTA_UPDATE_INFO_SZ (size_t) sizeof(F_FIOT_UPDATE_INFO)
#define F_SOFT_AP_CFG_SZ (size_t) sizeof(F_WIFI_CONFIG_V2)
#define F_SOFT_AP_LOGIN_PAGE_SZ F_SOFT_AP_CFG_SZ
#define F_WIFI_WIFI_CFG_SZ F_SOFT_AP_LOGIN_PAGE_SZ
#define F_CLOUD_FILE_PRIVATE_KEY_SZ (size_t)sizeof(F_FILE_PRIVATE_KEY_V2)
#define F_SSL_PRIVATE_KEY_SZ (size_t)sizeof(F_SSL_PRIVATE_KEY)
#define F_TRUSTED_KEY_SZ (size_t)sizeof(F_TRUSTED_KEY)
#define F_SELF_ECDSA_KEY_PAIR_SZ (size_t)sizeof(F_SELF_ECDSA_KEY_PAIR)
#define F_PARTITION_BLOCK_SZ (size_t) sizeof(F_PARTITION_BLOCK)
#define F_USER_DATA_BLOCK_SZ (size_t)(F_PARTITION_BLOCK_SZ-F_HEADER_SZ)

