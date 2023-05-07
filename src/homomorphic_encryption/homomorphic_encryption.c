#include <homomorphic_encryption/homomorphic_encryption.h>
#include <stdlib.h>



static const unsigned char _bfv_index_map[8]={0,4,2,6,1,5,3,7};
static const unsigned char _bfv_roots_of_unity[8]={1,249,64,2,241,128,4,225};
static const unsigned char _bfv_roots_of_unity_inverse[8]={1,32,253,129,16,255,193,8};



static unsigned int _random_uniform32(void){
	return rand()^(rand()<<8)^(rand()<<16)^(rand()<<24);
}



static int _random_triangle(void){
	unsigned int n=rand()&3;
	return (n&1)*((n&2)-1);
}



static void _process_encoder_decoder(unsigned short int* buffer,const unsigned char* roots_of_unity){
	unsigned int i=1;
	for (unsigned int j=0;j<3;j++){
		for (unsigned int k=0;k<8;k+=(i<<1)){
			for (unsigned int l=0;l<i;l++){
				int factor=roots_of_unity[l<<(3-j)]*((unsigned int)buffer[i|k|l]);
				buffer[i|k|l]=(((buffer[k|l]-factor)%257)+257)%257;
				buffer[k|l]=(buffer[k|l]+factor)%257;
			}
		}
		i<<=1;
	}
}



void bfv_init(bfv_config_t* out){
	for (unsigned int i=0;i<8;i++){
		out->public_key[1].data[i]=_random_uniform32();
		out->secret_key.data[i]=_random_triangle();
		out->relin_keys[0][1].data[i]=_random_uniform32();
		out->relin_keys[1][1].data[i]=_random_uniform32();
	}
	for (unsigned int i=0;i<8;i++){
		unsigned int coeff_pk0=_random_triangle();
		unsigned int coeff_sk_sq=0;
		unsigned int coeff_rl00=-_random_triangle();
		unsigned int coeff_rl10=-_random_triangle();
		for (unsigned int j=0;j<=i;j++){
			unsigned int coeff_sk=out->secret_key.data[j];
			coeff_pk0-=coeff_sk*out->public_key[1].data[i-j];
			coeff_sk_sq+=coeff_sk*out->secret_key.data[i-j];
			coeff_rl00+=coeff_sk*out->relin_keys[0][1].data[i-j];
			coeff_rl10+=coeff_sk*out->relin_keys[1][1].data[i-j];
		}
		for (unsigned int j=i+1;j<8;j++){
			unsigned int coeff_sk=out->secret_key.data[j];
			coeff_pk0+=coeff_sk*out->public_key[1].data[i-j+8];
			coeff_sk_sq-=coeff_sk*out->secret_key.data[i-j+8];
			coeff_rl00-=coeff_sk*out->relin_keys[0][1].data[i-j+8];
			coeff_rl10-=coeff_sk*out->relin_keys[1][1].data[i-j+8];
		}
		out->public_key[0].data[i]=coeff_pk0;
		out->relin_keys[0][0].data[i]=coeff_sk_sq-coeff_rl00;
		out->relin_keys[1][0].data[i]=(coeff_sk_sq<<16)-coeff_rl10;
	}
}



void bfv_decode(const bfv_config_t* config,const bfv_ciphertext_t* data,unsigned short int* out){
	for (unsigned int i=0;i<8;i++){
		unsigned int coeff=data->data[0].data[i];
		for (unsigned int j=0;j<=i;j++){
			coeff+=data->data[1].data[j]*config->secret_key.data[i-j];
		}
		for (unsigned int j=i+1;j<8;j++){
			coeff-=data->data[1].data[j]*config->secret_key.data[i-j+8];
		}
		coeff=(coeff+(((unsigned long long int)coeff)<<8))>>31;
		out[_bfv_index_map[i]]=(((coeff>>1)+(coeff&1))*_bfv_roots_of_unity[i])%257;
	}
	_process_encoder_decoder(out,_bfv_roots_of_unity);
}



void bfv_encode(const bfv_config_t* config,const unsigned short int* data,bfv_ciphertext_t* out){
	unsigned short int buffer[8];
	unsigned int randomness_vector[8];
	for (unsigned int i=0;i<8;i++){
		buffer[i]=data[_bfv_index_map[i]];
		randomness_vector[i]=_random_triangle();
	}
	_process_encoder_decoder(buffer,_bfv_roots_of_unity_inverse);
	for (unsigned int i=0;i<8;i++){
		unsigned int coeff0=_random_triangle();
		unsigned int coeff1=_random_triangle();
		for (unsigned int j=0;j<=i;j++){
			coeff0+=config->public_key[0].data[j]*randomness_vector[i-j];
			coeff1+=config->public_key[1].data[j]*randomness_vector[i-j];
		}
		for (unsigned int j=i+1;j<8;j++){
			coeff0-=config->public_key[0].data[j]*randomness_vector[i-j+8];
			coeff1-=config->public_key[1].data[j]*randomness_vector[i-j+8];
		}
		out->data[0].data[i]=coeff0+(((((unsigned long long int)buffer[i])*_bfv_roots_of_unity_inverse[i]*225)%257)<<32)/257;
		out->data[1].data[i]=coeff1;
	}
}



void bfv_add(const bfv_ciphertext_t* c0,const bfv_ciphertext_t* c1,bfv_ciphertext_t* out){
	for (unsigned int i=0;i<8;i++){
		out->data[0].data[i]=c0->data[0].data[i]+c1->data[0].data[i];
		out->data[1].data[i]=c0->data[1].data[i]+c1->data[1].data[i];
	}
}



void bfv_mult(const bfv_config_t* config,const bfv_ciphertext_t* c0,const bfv_ciphertext_t* c1,bfv_ciphertext_t* out){
	bfv_polynomial_t c2;
	for (unsigned int i=0;i<8;i++){
		unsigned long long int coeff_c0=0;
		unsigned long long int coeff_c1=0;
		unsigned long long int coeff_c2=0;
		for (unsigned int j=0;j<=i;j++){
			coeff_c0+=((unsigned long long int)(c0->data[0].data[j]))*c1->data[0].data[i-j];
			coeff_c1+=((unsigned long long int)(c0->data[0].data[j]))*c1->data[1].data[i-j]+((unsigned long long int)(c0->data[1].data[j]))*c1->data[0].data[i-j];
			coeff_c2+=((unsigned long long int)(c0->data[1].data[j]))*c1->data[1].data[i-j];
		}
		for (unsigned int j=i+1;j<8;j++){
			coeff_c0-=((unsigned long long int)(c0->data[0].data[j]))*c1->data[0].data[i-j+8];
			coeff_c1-=((unsigned long long int)(c0->data[0].data[j]))*c1->data[1].data[i-j+8]+((unsigned long long int)(c0->data[1].data[j]))*c1->data[0].data[i-j+8];
			coeff_c2-=((unsigned long long int)(c0->data[1].data[j]))*c1->data[1].data[i-j+8];
		}
		coeff_c0=((coeff_c0+(coeff_c0<<8))>>31);
		coeff_c1=((coeff_c1+(coeff_c1<<8))>>31);
		coeff_c2=((coeff_c2+(coeff_c2<<8))>>31);
		out->data[0].data[i]=(coeff_c0>>1)+(coeff_c0&1);
		out->data[1].data[i]=(coeff_c1>>1)+(coeff_c1&1);
		c2.data[i]=(coeff_c2>>1)+(coeff_c2&1);
	}
	for (unsigned int i=0;i<8;i++){
		unsigned int coeff_0=0;
		unsigned int coeff_1=0;
		for (unsigned int j=0;j<=i;j++){
			unsigned int coeff_2_lo=c2.data[i-j]&0xffff;
			unsigned int coeff_2_hi=c2.data[i-j]>>16;
			coeff_0+=config->relin_keys[0][0].data[j]*coeff_2_lo+config->relin_keys[1][0].data[j]*coeff_2_hi;
			coeff_1+=config->relin_keys[0][1].data[j]*coeff_2_lo+config->relin_keys[1][1].data[j]*coeff_2_hi;
		}
		for (unsigned int j=i+1;j<8;j++){
			unsigned int coeff_2_lo=c2.data[i-j+8]&0xffff;
			unsigned int coeff_2_hi=c2.data[i-j+8]>>16;
			coeff_0-=config->relin_keys[0][0].data[j]*coeff_2_lo+config->relin_keys[1][0].data[j]*coeff_2_hi;
			coeff_1-=config->relin_keys[0][1].data[j]*coeff_2_lo+config->relin_keys[1][1].data[j]*coeff_2_hi;
		}
		out->data[0].data[i]+=coeff_0;
		out->data[1].data[i]+=coeff_1;
	}
}
