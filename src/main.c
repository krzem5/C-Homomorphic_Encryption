#include <homomorphic_encryption/homomorphic_encryption.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>



int main(void){
	srand((unsigned int)time(NULL));
	bfv_config_t config;
	bfv_init(&config);
	const unsigned short vec1_raw[8]={2,5,8,2,5,16,4,5};
	const unsigned short vec2_raw[8]={256,2,3,4,5,6,7,8};
	bfv_ciphertext_t vec1;
	bfv_ciphertext_t vec2;
	bfv_encode(&config,vec1_raw,&vec1);
	bfv_encode(&config,vec2_raw,&vec2);
	bfv_ciphertext_t tmp;
	bfv_mult(&config,&vec1,&vec1,&tmp);
	bfv_ciphertext_t out;
	bfv_add(&tmp,&vec2,&out);
	unsigned short out_raw[8];
	bfv_decode(&config,&out,out_raw);
	printf("%u, %u, %u, %u, %u, %u, %u, %u | 3, 27, 67, 8, 30, 5, 23, 33\n",out_raw[0],out_raw[1],out_raw[2],out_raw[3],out_raw[4],out_raw[5],out_raw[6],out_raw[7]);
	return 0;
}
