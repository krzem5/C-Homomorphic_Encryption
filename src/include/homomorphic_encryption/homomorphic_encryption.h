#ifndef _HOMOMORPHIC_ENCRYPTION_HOMOMORPHIC_ENCRYPTION_H_
#define _HOMOMORPHIC_ENCRYPTION_HOMOMORPHIC_ENCRYPTION_H_ 1



typedef struct _BFV_POLYNOMIAL{
	unsigned int data[8];
} bfv_polynomial_t;



typedef struct _BFV_CONFIG{
	bfv_polynomial_t public_key[2];
	bfv_polynomial_t secret_key;
	bfv_polynomial_t relin_keys[2][2];
} bfv_config_t;



typedef struct _BFV_CIPHERTEXT{
	bfv_polynomial_t data[2];
} bfv_ciphertext_t;



void bfv_init(bfv_config_t* out);



void bfv_decode(const bfv_config_t* config,const bfv_ciphertext_t* data,unsigned short int* out);



void bfv_encode(const bfv_config_t* config,const unsigned short int* data,bfv_ciphertext_t* out);



void bfv_add(const bfv_ciphertext_t* c0,const bfv_ciphertext_t* c1,bfv_ciphertext_t* out);



void bfv_mult(const bfv_config_t* config,const bfv_ciphertext_t* c0,const bfv_ciphertext_t* c1,bfv_ciphertext_t* out);



#endif
