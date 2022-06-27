#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/types.h>
#include <openssl/pem.h>
#include <pony.h>
#include <stdio.h>

EVP_PKEY* create_rsa_keys(unsigned int bits);
X509* create_x509();
void remove_keys(EVP_PKEY *key);
void remove_x509(X509* x);
void x509_set_pubkey(X509* x, EVP_PKEY *key);
void x509_set_subject_name(X509* x, X509_NAME* name);
void x509_set_serial_number(X509* x, long number);
void x509_set_version(X509* x, long version);
void x509_set_notBefore(X509* x, uint64_t time);
void x509_set_notAfter(X509* x, uint64_t time);
X509_NAME* x509_create_name();
void x509_remove_name(X509_NAME* n);
void x509_set_name_country (X509_NAME* n, const unsigned char *country);
void x509_set_name_state (X509_NAME* n, const unsigned char *state);
void x509_set_name_common_name (X509_NAME* n, const unsigned char *commonName);
void x509_set_name_organization (X509_NAME* n, const unsigned char *organization);
void x509_set_name_organizational_unit (X509_NAME* n, const unsigned char * ou);
void x509_set_name_locality (X509_NAME* n, const unsigned char * locality);
BIO * create_bio();
void remove_bio(BIO* bp);
BUF_MEM * x509_write_PEM(X509* x, BIO* bp);
BUF_MEM * rsa_write_privateKey_PEM(BIO* bp, EVP_PKEY* key);

EVP_PKEY* create_rsa_keys(unsigned int bits) {
  EVP_PKEY *pk;
  pk = EVP_RSA_gen(bits);
  if (pk == NULL) {
    pony_error();
    return NULL;
  } else {
    return pk;
  }
}

void remove_keys(EVP_PKEY *key) {
  EVP_PKEY_free(key);
}

X509* create_x509() {
  X509 *x;
  x = X509_new();
  if (x == NULL) {
    pony_error();
    return x;
  } else {
    return x;
  }
}

void remove_x509(X509* x) {
  X509_free(x);
}

void x509_set_pubkey(X509* x, EVP_PKEY *key) {
  if (!X509_set_pubkey(x,key)) {
    pony_error();
  }
}

X509_NAME* x509_create_name() {
  X509_NAME* n = X509_NAME_new();
  if (n == NULL) {
    pony_error();
    return n;
  } else {
    return n;
  }
}

void x509_remove_name(X509_NAME* n) {
  X509_NAME_free(n);
}


void x509_set_name_country (X509_NAME* n, const unsigned char *country) {
  if (!X509_NAME_add_entry_by_txt(n, "C", MBSTRING_ASC,country, -1, -1, 0))  {
    pony_error();
  }
}

void x509_set_name_state (X509_NAME* n, const unsigned char *state) {
  if (!X509_NAME_add_entry_by_txt(n, "ST", MBSTRING_ASC, state, -1, -1, 0))  {
    pony_error();
  }
}

void x509_set_name_common_name (X509_NAME* n, const unsigned char *commonName) {
  if (!X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, commonName, -1, -1, 0))  {
    pony_error();
  }
}

void x509_set_name_organization (X509_NAME* n, const unsigned char *organization) {
  if (!X509_NAME_add_entry_by_txt(n, "O", MBSTRING_ASC, organization, -1, -1, 0))  {
    pony_error();
  }
}

void x509_set_name_organizational_unit (X509_NAME* n, const unsigned char * ou) {
  if (!X509_NAME_add_entry_by_txt(n, "OU", MBSTRING_ASC, ou, -1, -1, 0))  {
    pony_error();
  }
}

void x509_set_name_locality (X509_NAME* n, const unsigned char * locality) {
  if (!X509_NAME_add_entry_by_txt(n, "L", MBSTRING_ASC, locality, -1, -1, 0))  {
    pony_error();
  }
}

void x509_set_subject_name(X509* x, X509_NAME* name) {
  if (!X509_set_subject_name(x, name)) {
    pony_error();
  }
}

void x509_set_issuer_name(X509* x, X509_NAME* name) {
  if (!X509_set_issuer_name(x, name)) {
    pony_error();
  }
}


void x509_set_serial_number(X509* x, long number) {
  ASN1_INTEGER * num = ASN1_INTEGER_new();
  if (!ASN1_INTEGER_set(num, number)) {
    ASN1_INTEGER_free(num);
    pony_error();
    return;
  }
  if (!X509_set_serialNumber(x, num)) {
    ASN1_INTEGER_free(num);
    pony_error();
    return;
  }
  ASN1_INTEGER_free(num);
}

void x509_set_version(X509* x, long version) {
  if(!X509_set_version(x, version)) {
    pony_error();
  }
}

void x509_set_notBefore(X509* x, uint64_t time) {
  ASN1_TIME * cur = X509_getm_notBefore(x);

  if (!ASN1_TIME_set(cur, (time_t) time)) {
    pony_error();
    return;
  }
}

void x509_set_notAfter(X509* x, uint64_t time) {
  ASN1_TIME * cur = X509_getm_notAfter(x);

  if (!ASN1_TIME_set(cur, (time_t) time)) {
    pony_error();
    return;
  }
}
BIO * create_bio() {
  BIO* mem = BIO_new(BIO_s_mem());
  if (!mem) {
    pony_error();
    return NULL;
  }
  return mem;
}
void remove_bio(BIO* bp) {
    BIO_free(bp);
}

void sign_x509(X509 *x, EVP_PKEY *pkey) {
  if (!X509_sign(x, pkey, EVP_md5())) {
    pony_error();
    return;
  }
}

BUF_MEM * write_privateKey_PEM(BIO* bp, EVP_PKEY* key) {
  if (!PEM_write_bio_PrivateKey(bp, key, NULL, NULL, 0, 0, NULL)) {
    pony_error();
    return NULL;
  }
  BUF_MEM* mem;
  BIO_get_mem_ptr(bp, &mem);
  return mem;
}
BUF_MEM * write_pubKey_PEM(BIO* bp, EVP_PKEY* key) {
  if (!PEM_write_bio_PUBKEY(bp, key)) {
    pony_error();
    return NULL;
  }
  BUF_MEM* mem;
  BIO_get_mem_ptr(bp, &mem);
  return mem;
}

BUF_MEM * x509_write_PEM(X509* x, BIO* bp) {
  if (!PEM_write_bio_X509(bp, x)) {
    pony_error();
    return NULL;
  }

  BUF_MEM* mem;
  BIO_get_mem_ptr(bp, &mem);
  return mem;
}
