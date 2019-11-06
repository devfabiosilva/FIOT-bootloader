/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// This is a main library of FIOT bootloader tools to generate defautl factory configuration, generation of UID, import RSA 2048 private key,
//generate FIOT certificate using elliptic curves, verify sign site, import prime256r1 curves and verify uid tools.

//Qui 04 Jul 2019 21:03:52 -03
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"

#include "f_mbedtls_util.h"

#include "mbedtls/error.h"
#include "mbedtls/platform.h"

void fhex2str (unsigned char *ch, size_t size, char *out)
{
    size_t i = 0;

    for(i = 0; i < size; i++)
        sprintf(out + (i * 2), "%02x", (unsigned char)ch[i]);

    out[2*size] = 0;
}

int f_is_digit(char *str)
{
   size_t m=strlen(str);
   size_t i;

   for (i=0;i<m;i++)
     if (!isdigit(str[i]))
        return 0;

   return 1;
}

int f_str_to_long(char *str, int base, long int *val)
{
   char *p;

   if (base==10)
      if (f_is_digit(str)==0)
         return -1;

   *val=strtol(str, &p, base);

   if (errno==ERANGE)
      return 1;
   if (errno==EINVAL)
      return 2;

   return 0;
}

char *f_str_cpy_safe(char *dest, const char *src, size_t n)
{
   n--;
   dest[n]=0;
   strncpy(dest, src, n);
   return dest;
}

#define DEV_RANDOM_THRESHOLD 32

int dev_random_entropy_poll(void *data, unsigned char *output,
                             size_t len, size_t *olen)
{
    FILE *file;
    size_t ret, left = len;
    unsigned char *p = output;
    ((void) data);

    *olen = 0;

    file = fopen("/dev/random", "rb");
    if (file==NULL)
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    while (left>0) {
        /* /dev/random can return much less than requested. If so, try again */
        ret = fread(p, 1, left, file );
        if((ret==0)&&(ferror(file))) {
            fclose(file);
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }
        p += ret;
        left -= ret;
        sleep(1);
    }
    fclose( file );
    *olen = len;

    return 0;
}


int f_f_rand(void *fpers, uint8_t *output, size_t len)
{
    int err = 2;
    mbedtls_entropy_context *entropy;
    mbedtls_ctr_drbg_context *ctr_drbg;

    entropy=malloc(sizeof(mbedtls_entropy_context));

    if (!entropy)
       return 1;

    ctr_drbg=malloc(sizeof(mbedtls_ctr_drbg_context));

    if (!ctr_drbg)
       goto f_f_rand_EXIT1;

    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);

    err = mbedtls_entropy_add_source(entropy, dev_random_entropy_poll,
                                        NULL, DEV_RANDOM_THRESHOLD,
                                        MBEDTLS_ENTROPY_SOURCE_STRONG);

    if (err)
        goto f_f_rand_EXIT2;

    if (fpers)
        err=strlen(fpers);

    err=mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                               (const unsigned char *) fpers,
                               err);

    if (err)
        goto f_f_rand_EXIT2;

    err=mbedtls_ctr_drbg_random(ctr_drbg, output, len);

f_f_rand_EXIT2:
    mbedtls_ctr_drbg_free(ctr_drbg);
    mbedtls_entropy_free(entropy);

    free(ctr_drbg);
f_f_rand_EXIT1:
    free(entropy);
    return err;
}

uint32_t f_crc32_init(char *p, size_t len, uint32_t crcinit)
{
    uint32_t crc;

    extern const uint32_t crc32tab[256] asm("_binary_fcrc32data_dat_start");

    crc = crcinit ^ 0xFFFFFFFF;
    for (; len--; p++) {
        crc = ((crc >> 8) & 0x00FFFFFF) ^ crc32tab[(crc ^ (*p)) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

uint32_t f_crc32(char *p, size_t len)
{
    return f_crc32_init(p, len, 0);
}

int f_extract_public_key(mbedtls_ecp_keypair *ecp, char *out)
{
    size_t sz = mbedtls_mpi_size(&ecp->grp.P);

    int err;

    if (sz==0)
        return 0;

    err = mbedtls_mpi_write_binary(&ecp->Q.X, out, sz);

    if (err) {
        printf(F_KEY_EXTRACT_PK_ERROR, "Q(X)");
        return 0;
    }

    err = mbedtls_mpi_write_binary(&ecp->Q.Y, out + sz, sz);

    if (err) {
        printf(F_KEY_EXTRACT_PK_ERROR, "Q(Y)");
        return 0;
    }

    return 2*sz;
}

int f_extract_private_key(mbedtls_ecp_keypair *ecp, char *out)
{
    size_t sz = mbedtls_mpi_size(&ecp->grp.P);

    if (sz==0)
        return 0;

    if (mbedtls_mpi_write_binary(&ecp->d, out, sz)) {
        printf(F_KEY_EXTRACT_PK_ERROR, "d");
        return 0;
    }

    return sz;
}

char *f_sha256_digest(void *msg, size_t size)
{
    static char result256sum[32];

    mbedtls_sha256_context sha256;

    mbedtls_sha256_init(&sha256);

    mbedtls_sha256_starts_ret(&sha256, 0);

    mbedtls_sha256_update_ret(&sha256, msg, size);

    mbedtls_sha256_finish(&sha256, result256sum);

    mbedtls_sha256_free(&sha256);

    return result256sum;
}
// fabio comment
// 0 error | >0 size of signature
// if data_sz =0 then => data = sha256, else
int f_sign_ecdsa_v2(mbedtls_ecp_group_id gid, char *priv_key, void *data, size_t data_sz, char *signature) {

    mbedtls_ecdsa_context *ctx;
    mbedtls_mpi *r, *s;

    char *dgst;
    int sz=0, sz_tmp;//, sz_r, sz_s;
    int err;

    if (!priv_key) {
        printf("\nError NULL private key\n");
        return 0;
    }

    if (!data) {
        printf("\nError NULL data or hash\n");
        return 0;
    }

    if (!signature) {
        printf("\nError NULL signature\n");
        return 0;
    }

    ctx=malloc(sizeof(mbedtls_ecdsa_context));

    if (!ctx) {
        printf("\nError malloc \"mbedtls_ecdsa_context\"\n");
        return 0;
    }

    r=malloc(sizeof(mbedtls_mpi));

    if (!r) {
        printf("\nError malloc \"r\" vector\"");
        goto f_sign_ecdsa_v2_EXIT1;
    }

    s=malloc(sizeof(mbedtls_mpi));

    if (!s) {
        printf("\nError malloc \"s\" vector\"");
        goto f_sign_ecdsa_v2_EXIT2;
    }

    mbedtls_ecdsa_init(ctx);
    mbedtls_mpi_init(r);
    mbedtls_mpi_init(s);

    mbedtls_ecp_group_load(&ctx->grp, gid);

    sz_tmp = mbedtls_mpi_size(&ctx->grp.P);

    err = mbedtls_mpi_read_binary(&ctx->d, priv_key, sz_tmp);

    if (err) {
       printf("\nError reading private key %d\n", err);
       goto f_sign_ecdsa_v2_EXIT3;
    }

    if (data_sz)
       dgst=f_sha256_digest(data, data_sz);
    else
       dgst=(char *)data;

    err=mbedtls_ecdsa_sign(&ctx->grp, r, s, &ctx->d, dgst, 32, f_f_rand, "*7xcK]f_mbedtls_private_keyZ|signature@_sign/##");

    if (err) {
        printf("\nError on signing data/hash %d\n", err);
        goto f_sign_ecdsa_v2_EXIT3;
    }

    err = mbedtls_mpi_write_binary(r, signature, sz_tmp);

    if (err) {
        printf("\nError writing \"r\" on stream signature %d\n", err);
        goto f_sign_ecdsa_v2_EXIT3;
    }

    err = mbedtls_mpi_write_binary(s, signature+sz_tmp, sz_tmp);

    if (err) {
        printf("\nError writing \"s\" on stream signature %d\n", err);
        goto f_sign_ecdsa_v2_EXIT3;
    }

    sz=2*sz_tmp;

f_sign_ecdsa_v2_EXIT3:
    mbedtls_mpi_free(s);
    mbedtls_mpi_free(r);
    mbedtls_ecdsa_free(ctx);

    memset(s, 0, sizeof(mbedtls_mpi));
    memset(r, 0, sizeof(mbedtls_mpi));
    memset(ctx, 0, sizeof(mbedtls_ecdsa_context));

    free(s);
f_sign_ecdsa_v2_EXIT2:
    free(r);
f_sign_ecdsa_v2_EXIT1:
    free(ctx);
    return sz;
}

f_verify_cert_sig_err
f_verify_uECC_using_mbedTLS(uint8_t *pub_key, uint8_t *dgst, uint8_t *sig)
{
    int err=F_ECC_ERR_MALLOC;
    mbedtls_mpi *r, *s;
    mbedtls_ecdsa_context *ecdsa_context;

    r=malloc(sizeof(mbedtls_mpi));

    if (!r)
       return err;

    s=malloc(sizeof(mbedtls_mpi));

    if (!s)
        goto f_verify_uECC_using_mbedTLS_EXIT_1;

    ecdsa_context=malloc(sizeof(mbedtls_ecdsa_context));

    if (!ecdsa_context)
        goto f_verify_uECC_using_mbedTLS_EXIT_2;

    mbedtls_mpi_init(r);
    mbedtls_mpi_init(s);

    mbedtls_ecdsa_init(ecdsa_context);

    err = mbedtls_mpi_read_binary(r, sig, 32);

    if (err) {
        err = F_ECC_ERR_READ_BINARY_R;
        printf("Erro em ler r \"mbedtls_mpi_read_binary\" %d", err);
        goto f_verify_uECC_using_mbedTLS_EXIT;
    }

    err = mbedtls_mpi_read_binary(s, sig+32, 32);

    if (err) {
        err = F_ECC_ERR_READ_BINARY_S;
        printf("Erro em ler s \"mbedtls_mpi_read_binary\" %d", err);
        goto f_verify_uECC_using_mbedTLS_EXIT;
    }

    mbedtls_ecp_group_load(&ecdsa_context->grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_mpi_read_binary(&ecdsa_context->Q.X, pub_key, 32);
    mbedtls_mpi_read_binary(&ecdsa_context->Q.Y, pub_key + 32, 32);
    mbedtls_mpi_lset(&ecdsa_context->Q.Z, 1);

    err = mbedtls_ecdsa_verify(&ecdsa_context->grp, dgst, 32, &ecdsa_context->Q, r, s);

    if (err) {
        err = F_ECC_ERR_FAIL;
        //printf("Erro de verificação %d", err);
    } else {
        err = F_ECC_ERR_OK;
        //printf("Verificação OK!");
    }

f_verify_uECC_using_mbedTLS_EXIT:
    mbedtls_ecdsa_free(ecdsa_context);
    mbedtls_mpi_free(s);
    mbedtls_mpi_free(r);

    memset(ecdsa_context, 0, sizeof(mbedtls_ecdsa_context));
    memset(s, 0, sizeof(mbedtls_mpi));
    memset(r, 0, sizeof(mbedtls_mpi));

    free(ecdsa_context);
f_verify_uECC_using_mbedTLS_EXIT_2:
    free(s);
f_verify_uECC_using_mbedTLS_EXIT_1:
    free(r);
    return err;
}

f_verify_cert_sig_err f_verify_ecdsa_v2(mbedtls_ecp_group_id gid, char *public_key, void *data, size_t data_sz, char *signature)
{
    int err;
    mbedtls_mpi *r, *s;
    mbedtls_ecdsa_context *ecdsa_context;
    size_t sz_tmp;
    char *dgst;

    if (!public_key)
       return F_ECC_NULL_PUBLIC_KEY;

    if (!data)
       return F_ECC_NULL_DATA;

    if (!signature)
       return F_ECC_NULL_SIG;

    err=F_ECC_ERR_MALLOC;

    r=malloc(sizeof(mbedtls_mpi));

    if (!r)
       return err;

    s=malloc(sizeof(mbedtls_mpi));

    if (!s)
        goto f_verify_uECC_using_mbedTLS_EXIT_1;

    ecdsa_context=malloc(sizeof(mbedtls_ecdsa_context));

    if (!ecdsa_context)
        goto f_verify_uECC_using_mbedTLS_EXIT_2;

    mbedtls_mpi_init(r);
    mbedtls_mpi_init(s);

    mbedtls_ecdsa_init(ecdsa_context);

    err=mbedtls_ecp_group_load(&ecdsa_context->grp, gid);

    if (err) {
        err=F_ECC_ERR_GRP_LOAD;
        goto f_verify_uECC_using_mbedTLS_EXIT;
    }

    sz_tmp=mbedtls_mpi_size(&ecdsa_context->grp.P);

    err=mbedtls_mpi_read_binary(&ecdsa_context->Q.X, public_key, sz_tmp);

    if (err) {
       err=F_ECC_ERR_READ_BINARY_Q_X;
       goto f_verify_uECC_using_mbedTLS_EXIT;
    }

    err=mbedtls_mpi_read_binary(&ecdsa_context->Q.Y, public_key + sz_tmp, sz_tmp);

    if (err) {
       err=F_ECC_ERR_READ_BINARY_Q_Y;
       goto f_verify_uECC_using_mbedTLS_EXIT;
    }

    err=mbedtls_mpi_lset(&ecdsa_context->Q.Z, 1);

    if (err) {
       err=F_ECC_ERR_SET_BINARY_Q_Z_1;
       goto f_verify_uECC_using_mbedTLS_EXIT;
    }

    err = mbedtls_mpi_read_binary(r, signature, sz_tmp);

    if (err) {
        err = F_ECC_ERR_READ_BINARY_R;
        printf("Erro em ler r \"mbedtls_mpi_read_binary\" %d", err);
        goto f_verify_uECC_using_mbedTLS_EXIT;
    }

    err = mbedtls_mpi_read_binary(s, signature+sz_tmp, sz_tmp);

    if (err) {
        err = F_ECC_ERR_READ_BINARY_S;
        printf("Erro em ler s \"mbedtls_mpi_read_binary\" %d", err);
        goto f_verify_uECC_using_mbedTLS_EXIT;
    }

    if (data_sz)
       dgst=f_sha256_digest(data, data_sz);
    else
       dgst=(char *)data;

    err = mbedtls_ecdsa_verify(&ecdsa_context->grp, dgst, 32, &ecdsa_context->Q, r, s);

    if (err) {
        err = F_ECC_ERR_FAIL;
        //printf("Erro de verificação %d", err);
    } else {
        err = F_ECC_ERR_OK;
        //printf("Verificação OK!");
    }

f_verify_uECC_using_mbedTLS_EXIT:
    mbedtls_ecdsa_free(ecdsa_context);
    mbedtls_mpi_free(s);
    mbedtls_mpi_free(r);

    memset(ecdsa_context, 0, sizeof(mbedtls_ecdsa_context));
    memset(s, 0, sizeof(mbedtls_mpi));
    memset(r, 0, sizeof(mbedtls_mpi));

    free(ecdsa_context);
f_verify_uECC_using_mbedTLS_EXIT_2:
    free(s);
f_verify_uECC_using_mbedTLS_EXIT_1:
    free(r);
    return err;
}

//TIMESTAMP(8)|LN(4)|RAND(4)|CRC(4)
// fabio: You must specify LN
int generate_uid(FIOT_UID *uid)
{
   uint32_t tmp32[2];
   uint32_t crc32_tmp;
   int err;
   const char *peer="7.!xK{Ts%~]zQkJlA(1=+)2@?|c>:cbE,\"#xfGw}/]0I^M";

   if (err=f_f_rand((void *)peer, (uint8_t *)&uid->serial, sizeof(uint32_t)))
      return err;

   uid->production_no|=F_VENDOR_ID;

   tmp32[0]=(~uid->production_no)^(uid->serial);
   tmp32[1]=uid->serial;
   crc32_tmp=f_crc32((char *)tmp32, sizeof(tmp32));
   //printf("\nCRC32 1 = %04x %d\n", (int)crc32_tmp, (int)crc32_tmp);

   if (uid->timestamp==0)
      uid->timestamp=(uint64_t)time(NULL);
   //printf("\nUID creation date: %s\n", ctime(&uid->timestamp));

   uid->timestamp^=(((uint64_t)crc32_tmp)<<32);

   tmp32[1]=(uid->production_no)^(~uid->serial);
   tmp32[0]=uid->serial;
   crc32_tmp=f_crc32((char *)tmp32, sizeof(tmp32));
   //printf("\nCRC32 2 = %04x %d\n", (int)crc32_tmp, (int)crc32_tmp);

   uid->timestamp^=(uint64_t)crc32_tmp;

   uid->production_no^=(~(uid->serial));

   uid->crc32=f_crc32((char *)uid, sizeof(FIOT_UID)-sizeof(uint32_t));

   return 0;
}

int f_str_to_hex(char *str, uint8_t *hex_stream)
{

   char ch;
   size_t len = strlen(str);
   size_t i;

   for (i=0;i<len;i++) {
      ch=str[i];

      if (ch>'f')
         return 1;

      if (ch<'0')
         return 2;

      ch-='0';

      if (ch>9) {
         if (ch&0x30) {

            if ((ch&0x30)==0x20)
               return 4;

            ch&=0x0F;

            ch+=9;

            if (ch<10)
               return 5;
            if (ch>15)
               return 6;

         } else
            return 3;
      }

      (i&1)?(hex_stream[i>>1]|=(uint8_t)ch):(hex_stream[i>>1]=(uint8_t)(ch<<4));
   }

   return 0;

}

int get_uid(FIOT_UID *uid)
{

   uint32_t tmp32[2];
   uint64_t tmp64;

   if (uid->crc32^f_crc32((char *)uid, sizeof(FIOT_UID)-sizeof(uint32_t)))
      return 1;

   uid->production_no^=(~(uid->serial));

//
   if ((uid->production_no&0xFFFF0000)^F_DEFAULT_VENDOR_ID)
      return 2;
//

   tmp32[0]=uid->serial;
   tmp32[1]=(uid->production_no)^(~(uid->serial));

   tmp64=(uint64_t)f_crc32((char *)tmp32, sizeof(tmp32));

   tmp32[0]=(~uid->production_no)^(uid->serial);
   tmp32[1]=uid->serial;

   tmp64|=((uint64_t)f_crc32((char *)tmp32, sizeof(tmp32)))<<32;

   uid->timestamp^=tmp64;

   return 0;

}

int f_strtouid(char *str, FIOT_UID *uid)
{
   if (strlen(str)^(2*sizeof(FIOT_UID)))
      return 60;

   return f_str_to_hex(str, (uint8_t *)uid);
}

int show_uid_info(FIOT_UID *uid)
{
   int err;
   char buf[2*sizeof(FIOT_UID)+1];
   FIOT_UID uid_info;

   printf("\nReading uid information ...");

   memcpy(&uid_info, uid, sizeof(uid_info));

   if (err=get_uid(&uid_info)) {
      printf(FAIL);
      printf("\nError. Wrong uid_info %d\n", err);
      return err;
   }

   printf(OK);

   fhex2str((unsigned char *)uid, sizeof(FIOT_UID), buf);
   printf("\n\n================== UID DETAILS ==================\n\n");
   printf("\n\nUID VALUE %s\n\n", buf);
   printf("UID Timestamp: %s\n", ctime((time_t *)&uid_info.timestamp));
   printf("UID Production No.: %d\n", (int)uid_info.production_no&0x0000FFFF);
   printf("UID Serial No.: %04x\n", (int)uid_info.serial);
   printf("UID Vendor ID: %04x\n", (int)uid_info.production_no>>16);
   printf("UID CRC32: %04x\n", (int)uid_info.crc32);
   printf("\n\n================ END UID DETAILS ================\n\n");

   return 0;
}

int verify_valid_rsa_private_key_file(char *file_name)
{

   char buf[2*MBEDTLS_ECDSA_MAX_LEN+1];
   mbedtls_pk_context rsa_priv_key;
   int err;

   mbedtls_pk_init(&rsa_priv_key);

   err=mbedtls_pk_parse_keyfile(&rsa_priv_key, file_name, NULL);

   if (err) {
     mbedtls_pk_free(&rsa_priv_key);
     mbedtls_strerror(err, (char *)buf, sizeof(buf));
     mbedtls_printf("Error opening file. Is this private key PEM file?\n ! mbedtls_pk_parse_keyfile returned -0x%04x - %s\n\n", -err, buf);
     return 1;
   }

   if (mbedtls_pk_get_type(&rsa_priv_key)!=MBEDTLS_PK_RSA) {
     mbedtls_pk_free(&rsa_priv_key);
     printf("\nError: File \"%s\" is not an RSA private key\n", file_name);
     return 2;
   }

   if ((err=(int)mbedtls_rsa_get_len(mbedtls_pk_rsa(rsa_priv_key)))!=RSA_PRIV_KEY_MAX) {
      mbedtls_pk_free(&rsa_priv_key);
      printf("RSA private key must be %d\nError RSA(%d) != RSA_PRIV_KEY_MAX(%d)\n",(int)RSA_PRIV_KEY_MAX*8, (int)RSA_PRIV_KEY_MAX, err);
      return 3;
   }

   mbedtls_pk_free(&rsa_priv_key);
   return 0;
}

int f_get_file_size(FILE *f, long int *sz)
{
   int err;
   err=fseek(f, 0L, SEEK_END);

   if (err)
      return 1;

   *sz=ftell(f);

   err=fseek(f, 0L, SEEK_SET);

   if (err)
      return 2;

   return 0;
}
