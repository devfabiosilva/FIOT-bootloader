/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// This is a main library of FIOT bootloader tools to generate defautl factory configuration, generation of UID, import RSA 2048 private key,
//generate FIOT certificate using elliptic curves, verify sign site, import prime256r1 curves and verify uid tools.


#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"

#define OK " [ ok ]"
#define FAIL " [ fail ]"

#define F_VENDOR_ID (uint32_t)0x2FB50000
#define F_DEFAULT_VENDOR_ID (uint32_t)F_VENDOR_ID

#define F_KEY_EXTRACT_PK_ERROR "\nError in extract %s in ecp key\n"

#define CERTIFICATE_MAGIC_SZ 16
#define CERTIFICATE_DESCRIPTION_SZ 72

#if (MBEDTLS_ECDSA_MAX_LEN&0x0000000F)
    #define F_EDSA_FILE_MAX_LEN ((MBEDTLS_ECDSA_MAX_LEN&0xFFFFFFF0) + 0x00000010)
#else
    #define F_EDSA_FILE_MAX_LEN (MBEDTLS_ECDSA_MAX_LEN)
#endif

#define NUM_MPK 3

#define RSA_PRIV_KEY_MAX (size_t)256 //2048/8

static const char CERTIFICATE_MAGIC[CERTIFICATE_MAGIC_SZ]={'_','f','i','o','t','s','i','g','n','e','d','c','e','r','t','_'};

static const char *CERTIFICATE_DESCRIPTION = "FIOT - Fábio Pereira IoT Gateway platform - 2019 | Use Bitcoin";

typedef uint8_t F_PUBLIC_KEY[64];

typedef enum f_verify_cert_sig_err_t {
     F_ECC_ERR_OK = 0,
     F_ECC_ERR_FAIL = 16,
     F_ECC_ERR_READ_BINARY_Q_X,
     F_ECC_ERR_READ_BINARY_Q_Y,
     F_ECC_ERR_SET_BINARY_Q_Z_1,
     F_ECC_ERR_READ_BINARY_R,
     F_ECC_ERR_READ_BINARY_S,
     F_ECC_ERR_MALLOC,
     F_ECC_ERR_GRP_LOAD,
     F_ECC_NULL_PUBLIC_KEY,
     F_ECC_NULL_DATA,
     F_ECC_NULL_SIG
} f_verify_cert_sig_err;

typedef struct f_fiot_certificate_t {
    uint8_t magic[CERTIFICATE_MAGIC_SZ];
    uint8_t certificate_description[CERTIFICATE_DESCRIPTION_SZ];
    uint8_t reserved[16];
    uint8_t pkey[F_EDSA_FILE_MAX_LEN];
    uint32_t pkey_type;
    uint32_t version;
    uint64_t create_At;
    uint64_t expire_At;
    uint8_t signature[64];
}__attribute__((packed)) FIOT_CERTIFICATE;

_Static_assert(sizeof(FIOT_CERTIFICATE) == 336, "this struct should be 336 bytes");


typedef struct fiot_uid_t {
   uint64_t timestamp;
   uint32_t production_no;
   uint32_t serial;
   uint32_t crc32;
} __attribute__( (packed) ) FIOT_UID;

_Static_assert(sizeof(FIOT_UID)==20, "FIOT_UID should be 20 bytes long");

void fhex2str (unsigned char *ch, size_t size, char *out);
int f_extract_public_key(mbedtls_ecp_keypair *ecp, char *out);
int f_extract_private_key(mbedtls_ecp_keypair *ecp, char *out);
char *f_sha256_digest(void *msg, size_t size);
int f_sign_ecdsa_v2(mbedtls_ecp_group_id gid, char *priv_key, void *data, size_t data_sz, char *signature);
f_verify_cert_sig_err f_verify_uECC_using_mbedTLS(uint8_t *pub_key, uint8_t *dgst, uint8_t *sig);
f_verify_cert_sig_err f_verify_ecdsa_v2(mbedtls_ecp_group_id gid, char *public_key, void *data, size_t data_sz, char *signature);
int f_f_rand(void *fpers, uint8_t *output, size_t len);
uint32_t f_crc32(char *p, size_t len);
int f_is_digit(char *str);
int f_str_to_long(char *str, int base, long int *val);
int generate_uid(FIOT_UID *uid);
int get_uid(FIOT_UID *uid);
int f_strtouid(char *str, FIOT_UID *uid);
int show_uid_info(FIOT_UID *uid);
int verify_valid_rsa_private_key_file(char *file_name);
int f_get_file_size(FILE *f, long int *sz);
char *f_str_cpy_safe(char *dest, const char *src, size_t n);

