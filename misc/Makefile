#
#	AUTHOR: Fábio Pereira da Silva
#	YEAR: 2019
#	LICENSE: MIT
#	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
#

# Generating tools
#Qui 04 Jul 2019 00:09:11 -03 
CC=gcc
#CD=cd
STRIP=strip
FILENAME=fiot_gen_cert
VERIFY_CERT_FILENAME=fiot_verify_cert
EXPORT_MASTER_PK=fiot_export_master_public_key
SIGN_SITE=fiot_sign_site
VERIFY_SIGN_SITE=fiot_verify_signed_site
GEN_UID=fiot_gen_uid
VERIFY_UID=fiot_verify_uid
GEN_DEFAULT=fiot_gen_default_conf
FPATH=/usr/bin/
INCLUDEDIR=$(PWD)/include/
LD=ld -r -b binary
#AR=ar rcs
#LIBANAME=fcrypt1.0
LIBSONAME=fcrypt1.1

include ./fproject.mk

OBJEXT ?= .o

COBJS = $(CSRCS:.c=$(OBJEXT))

all: part main

%.o: %.c
	@$(CC) -fPIC -I$(INCLUDEDIR) -c $< -o $@ -Os
#@$(CC) -I$(INCLUDEDIR) -c $< -o $@ -Os
	@echo "CC $<"

part:$(COBJS)
	@echo "Entering fiot linked data ..."
	$(MAKE) -C fiot_raw_data

main: part
	@echo "Almost finishing ..."
#@echo "Creating static library..."
#$(AR) lib$(LIBANAME).a $(wildcard $(RAWDATDIR)/*.o) $(COBJS)
	@echo "Creating SO file lib$(LIBSONAME).so"
	$(CC) -o lib$(LIBSONAME).so -shared -Os -I$(INCLUDEDIR) $(wildcard $(RAWDATDIR)/*.o) $(COBJS)
	@echo "Striping SO file lib$(LIBSONAME).so"
	$(STRIP) lib$(LIBSONAME).so
	@echo "Creating $(FILENAME)"
	$(CC) -o $(FILENAME) $(FILENAME).c -I$(INCLUDEDIR) -Os -l$(LIBSONAME) -L$(PWD)
	@echo "Creating $(VERIFY_CERT_FILENAME)"
	$(CC) -o $(VERIFY_CERT_FILENAME) $(VERIFY_CERT_FILENAME).c -I$(INCLUDEDIR) -Os -l$(LIBSONAME) -L$(PWD)
	@echo "Creating $(EXPORT_MASTER_PK)"
	$(CC) -o $(EXPORT_MASTER_PK) $(EXPORT_MASTER_PK).c -I$(INCLUDEDIR) -Os -l$(LIBSONAME) -L$(PWD)
	@echo "Creating $(SIGN_SITE)"
	$(CC) -o $(SIGN_SITE) $(SIGN_SITE).c -I$(INCLUDEDIR) -Os -l$(LIBSONAME) -L$(PWD)
	@echo "Creating $(VERIFY_SIGN_SITE)"
	$(CC) -o $(VERIFY_SIGN_SITE) $(VERIFY_SIGN_SITE).c -I$(INCLUDEDIR) -Os -l$(LIBSONAME) -L$(PWD)
	@echo "Creating $(GEN_UID)"
	$(CC) -o $(GEN_UID) $(GEN_UID).c -I$(INCLUDEDIR) -Os -l$(LIBSONAME) -L$(PWD)
	@echo "Creating $(VERIFY_UID)"
	$(CC) -o $(VERIFY_UID) $(VERIFY_UID).c -I$(INCLUDEDIR) -Os -l$(LIBSONAME) -L$(PWD)
	$(CC) -o $(GEN_DEFAULT) $(GEN_DEFAULT).c -I$(INCLUDEDIR) -Os -l$(LIBSONAME) -L$(PWD)

	$(STRIP) $(FILENAME)
	$(STRIP) $(VERIFY_CERT_FILENAME)
	$(STRIP) $(EXPORT_MASTER_PK)
	$(STRIP) $(SIGN_SITE)
	$(STRIP) $(VERIFY_SIGN_SITE)
	$(STRIP) $(GEN_UID)
	$(STRIP) $(VERIFY_UID)
	$(STRIP) $(GEN_DEFAULT)

#debug:
#	$(CC) -D DEBUG -o $(FILENAME) main.c $(LIBOPENSSL)
#	$(STRIP) $(FILENAME)

.PHONY: clean
clean:
	@echo "Entering $(RAWDATDIR)..."
	$(MAKE) -C fiot_raw_data clean
#rm lib$(LIBANAME).a
	rm lib$(LIBSONAME).so
	@echo "Removing program objs and $(FILENAME)..."
	rm -v $(FILENAME) $(COBJS) $(VERIFY_CERT_FILENAME)
	rm -v $(EXPORT_MASTER_PK) $(SIGN_SITE) $(VERIFY_SIGN_SITE)
	rm -v $(GEN_UID) $(VERIFY_UID)
	rm -v $(GEN_DEFAULT)

