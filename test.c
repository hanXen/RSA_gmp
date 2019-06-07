#include <stdio.h>
#include <string.h>
#include <time.h>
#include "KISA_SHA256.h"
#include "RSA.h"
#include "gmp.h"



clock_t elapsed; float sec;

#define START_WATCH \
{\
 elapsed = -clock(); \
}\

#define STOP_WATCH \
{\
 elapsed += clock();\
 sec = (float)elapsed/CLOCKS_PER_SEC;\
}\

#define PRINT_TIME(qstr) \
{\
 printf("\n[%s: %.5f s]\n",qstr,sec);\
}\

// a,b,>=0, a>=b
void test_sha256()
{
	int i;
	BYTE pszMessage[20];
	UINT uPlainTextLen;
	BYTE pszDigest[SHA256_DIGEST_VALUELEN];

	//pszmessage =='abc'
	sprintf_s(pszMessage, 20, "abcsdfsdfsdf");
	uPlainTextLen = strlen(pszMessage);

	SHA256_Encrpyt(pszMessage, uPlainTextLen, pszDigest);

	printf("\n");
	for (i = 0; i < SHA256_DIGEST_VALUELEN; i++)
		printf("%02x", pszDigest[i]);
	printf("\n");

}

// a,b,>=0, a>=b
void __mpz_add_new(mpz_t c, mpz_t a, mpz_t b)
{
	int   i, carry = 0;
	mpz_t out;

	mpz_init2(out, (mpz_size(a) + 1) << 5);

	for (i = 0; i < mpz_size(b); i++)
	{
		if (carry) {
			out->_mp_d[i] = a->_mp_d[i] + b->_mp_d[i] + 1;
			carry = a->_mp_d[i] >= (~b->_mp_d[i]);
		}
		else {
			out->_mp_d[i] = a->_mp_d[i] + b->_mp_d[i];
			carry = out->_mp_d[i] < a->_mp_d[i];
		}
	}

	for (; i < mpz_size(a); i++)
	{
		out->_mp_d[i] = a->_mp_d[i] + carry;
		carry = out->_mp_d[i] < carry;
	}

	if (carry) {
		out->_mp_d[i] = 1;
		out->_mp_size = mpz_size(a) + 1;
	}
	else
		out->_mp_size = mpz_size(a);

	mpz_set(c, out);
	mpz_clear(out);
}

// a,b,>=0, a>=b
void __mpz_sub_new(mpz_t c, mpz_t a, mpz_t b)
{
	int i, borrow = 0, tmp;
	mpz_t out;

	mpz_init2(out, (mpz_size(a) + 1) << 5);

	for (i = 0; i < mpz_size(b); i++)
	{
		out->_mp_d[i] = a->_mp_d[i] - b->_mp_d[i] - borrow;
		if (borrow) {
			borrow = (a->_mp_d[i] <= b->_mp_d[i]);
		}
		else {
			borrow = (a->_mp_d[i] < b->_mp_d[i]);
		}
	}
	for (; i < mpz_size(a); i++) {
		out->_mp_d[i] = a->_mp_d[i] - borrow;
		borrow = (a->_mp_d[i] < borrow);
	}

	out->_mp_size = mpz_size(a);
	for (i = out->_mp_size - 1; i >= 0; i--) {
		if (out->_mp_d[i] == 0) out->_mp_size--;
		else break;
	}

	mpz_set(c, out);
	mpz_clear(out);
}


// a,b, in Z
void mpz_add_new(mpz_t c, mpz_t a, mpz_t b)
{
	if (mpz_sgn(a) == mpz_sgn(b)) {
		//부호가 같은 경우
		if (mpz_size(a) >= mpz_size(b)) {
			__mpz_add_new(c, a, b);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}
		else {
			__mpz_add_new(c, b, a);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}
	}
	else {
		//부호가 다른 경우

		if (mpz_cmpabs(a, b) >= 0)
		{
			__mpz_sub_new(c, a, b);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}
		else {
			__mpz_sub_new(c, b, a);
			c->_mp_size = c->_mp_size*mpz_sgn(b);
		}
	}

	return;
}

// a,b, in Z
void mpz_sub_new(mpz_t c, mpz_t a, mpz_t b)
{
	if (a->_mp_size == 0) {
		mpz_set(c, b);
		c->_mp_size = c->_mp_size*(-1);
		return;
	}

	if (mpz_sgn(a) == mpz_sgn(b)) {
		//부호가 같은 경우
		if (mpz_cmpabs(a, b) >= 0)
		{
			__mpz_sub_new(c, a, b);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}
		else {
			__mpz_sub_new(c, b, a);
			c->_mp_size = c->_mp_size*(0 - mpz_sgn(b));
		}
	}
	else {
		//부호가 다른 경우
		if (mpz_size(a) >= mpz_size(b)) {
			__mpz_add_new(c, a, b);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}
		else {
			__mpz_add_new(c, b, a);
			c->_mp_size = c->_mp_size*mpz_sgn(a);
		}

	}
}

void mpz_mul_new(mpz_t c, mpz_t a, mpz_t b)
{
	int i, j;
	int a_size, b_size;
	mpz_t out;
	unsigned long long int carry = 0;

	a_size = mpz_size(a);
	b_size = mpz_size(b);

	mpz_init2(out,((a_size+b_size)<<5)+1);
	for (i = 0; i < out->_mp_alloc; i++) out->_mp_d[i] = 0;
	for (i = 0; i < b_size; i++) {
		carry = 0;
		for (j = 0; j < a_size; j++) {
			carry = (unsigned long long int)(b->_mp_d[i]) * (unsigned long long int)(a->_mp_d[j])
				  + (unsigned long long int)out->_mp_d[i + j]
				  + ((unsigned long long int)carry>>32);
			out->_mp_d[i + j] = (unsigned int)carry;
		}
		out->_mp_d[i + j] = (unsigned int)((unsigned long long int)carry >> 32);
	}
	out->_mp_size = (a_size + b_size);
	if (out->_mp_d[out->_mp_size - 1] == 0) out->_mp_size--;
	out->_mp_size = out->_mp_size*mpz_sgn(a)*mpz_sgn(b);

	mpz_set(c, out);
	mpz_clear(out);
}

int mpz_ltor_binary_powm(mpz_t c, mpz_t a, mpz_t e, mpz_t n)
{
	int i, j;
	mpz_t out;

	mpz_init(out);

	out->_mp_d[0] = out->_mp_size = 1;

	i = mpz_size(e) - 1;
	for (; i >= 0; i--) {
		for (j = 31; j >= 0;j--) {
			mpz_mul(out, out, out);
			mpz_mod(out, out, n);
			if (e->_mp_d[i] & (1 << j)) {
				mpz_mul(out, out, a);
				mpz_mod(out, out, n);
			}
		}
	}
	mpz_set(c, out);
	mpz_clear(out);
}
void gmp_speed_test()
{
	mpz_t a, b, c, d;
	gmp_randstate_t state;
	int i;

	mpz_init(a);
	mpz_init(b);
	mpz_init(c);
	mpz_init(d);
	gmp_randinit_default(state);

	mpz_urandomb(a, state, 2048);
	mpz_urandomb(b, state, 2048);
	mpz_urandomb(c, state, 4096);

	START_WATCH;
	for (i = 0; i < 1000000; i++) mpz_add(d, a, b);
	STOP_WATCH;
	PRINT_TIME("mpz_add");

	START_WATCH;
	for (i = 0; i < 1000000; i++) mpz_sub(d, a, b);
	STOP_WATCH;
	PRINT_TIME("mpz_sub");

	START_WATCH;
	for (i = 0; i < 1000000; i++) mpz_mul(d, a, b);
	STOP_WATCH;
	PRINT_TIME("mpz_mul");

	START_WATCH;
	for (i = 0; i < 1000000; i++) mpz_mod(d, c, b);
	STOP_WATCH;
	PRINT_TIME("mpz_mod");

	START_WATCH;
	for (i = 0; i < 1000000; i++) mpz_invert(d, a, b);
	STOP_WATCH;
	PRINT_TIME("mpz_invert");

	mpz_clear(a); mpz_clear(b); mpz_clear(c); mpz_clear(d);
}

void test_add_sub()
{
	int i;
	mpz_t a, b, c, d;
	gmp_randstate_t state;

	mpz_init(a); mpz_init(b); mpz_init(c); mpz_init(d);
	gmp_randinit_default(state);

	for (i = 0; i < 100000; i++)
	{
		mpz_urandomb(a, state, 1024);
		a->_mp_size = a->_mp_d[0] & 0x1f;
		a->_mp_size = (a->_mp_d[0] & 0x1) ? (a->_mp_size) : (a->_mp_size *(-1));
		mpz_urandomb(b, state, 1024);
		b->_mp_size = a->_mp_d[0] & 0x1f;
		b->_mp_size = (b->_mp_d[0] & 0x1) ? (b->_mp_size) : (b->_mp_size *(-1));
		mpz_add(c, a, b);
		mpz_add_new(d, a, b);

		if (mpz_cmp(c, d)) {
			printf("false\n");
		}
		else {
			printf("true\n");
		}
	}
	for (i = 0; i < 1000000; i++)
	{
		mpz_urandomb(a, state, 1024);
		a->_mp_size = a->_mp_d[0] & 0x1f;
		a->_mp_size = (a->_mp_d[0] & 0x1) ? (a->_mp_size) : (a->_mp_size *(-1));
		mpz_urandomb(b, state, 1024);
		b->_mp_size = a->_mp_d[0] & 0x1f;
		b->_mp_size = (b->_mp_d[0] & 0x1) ? (b->_mp_size) : (b->_mp_size *(-1));

		mpz_sub(c, a, b);
		mpz_sub_new(d, a, b);

		if (mpz_cmp(c, d)) {
			printf("false\n");
		}
		else {
			printf("true\n");
		}
	}

	mpz_clear(a); mpz_clear(b); mpz_clear(c); mpz_clear(d);
	gmp_randclear(state);
}

void test_powm()
{
	int i;
	mpz_t c, a, e, n, d;
	gmp_randstate_t state;

	mpz_init(c); mpz_init(a); mpz_init(e); mpz_init(n); mpz_init(d);
	gmp_randinit_default(state);

	mpz_urandomb(n, state, 2048);
	for (i = 0; i < 100; i++) {
		mpz_urandomb(a, state, 2048);
		mpz_urandomb(e, state, 2048);

		mpz_ltor_binary_powm(c, a, e, n);
		mpz_powm(d, a, e, n);
		if (mpz_cmp(c, d)) {
			printf("false\n");
		}
		else {
			printf("true\n");
		}
	}

	mpz_clear(c); mpz_clear(a); mpz_clear(e); mpz_clear(n); mpz_clear(d);
	gmp_randclear(state);
}

void gmp_powm_speed_test()
{
	int i;
	mpz_t c, a, e, n, d;
	gmp_randstate_t state;

	mpz_init(c); mpz_init(a); mpz_init(e); mpz_init(n); mpz_init(d);
	gmp_randinit_default(state);

	mpz_urandomb(a, state, 2048);
	mpz_urandomb(n, state, 2048);
	mpz_urandomb(e, state, 2048);

	START_WATCH;
	for (i = 0; i < 100; i++) mpz_powm(d, a, e, n);
	STOP_WATCH;
	PRINT_TIME("mpz_powm");

	START_WATCH;
	for (i = 0; i < 100; i++) mpz_ltor_binary_powm(c, a, e, n);
	STOP_WATCH;
	PRINT_TIME("mpz_ltor_binary_powm");

	mpz_clear(c); mpz_clear(a); mpz_clear(e); mpz_clear(n); mpz_clear(d);
	gmp_randclear(state);
}

test_rsa_keygen()
{
	int RSA_SIZE;
	mpz_t m,mp,c;
	RSA_PUBKEY pub;
	RSA_PRIKEY pri;
	gmp_randstate_t state;

	mpz_init(m); mpz_init(mp); mpz_init(c);
	gmp_randinit_default(state);

	RSA_SIZE = 2048;
	RSA_KEY_init(&pub,&pri);
	RSA_KEY_gen(&pub, &pri,2048);

	// 메시지 선택
	mpz_urandomm(m, state,pri.n);
	//암호화
	mpz_powm(c, m, pub.e, pub.n);
	//복호화
	mpz_powm(mp, c, pri.d, pri.n);
	
	if (mpz_cmp(m, mp))
		printf("fail\n");
	else
		printf("pass\n");

	gmp_printf("p = %Zx\n",pri.p);
	gmp_printf("q = %Zx\n", pri.q);
	gmp_printf("n = %Zx\n", pri.n);
	gmp_printf("e = %Zx\n", pri.e);
	gmp_printf("d = %Zx\n\n", pri.d);
	gmp_printf("e = %Zx\n", pub.e);
	gmp_printf("n = %Zx\n\n", pub.n);
	gmp_printf("m  = %Zx\n", m);
	gmp_printf("c = %Zx\n", c);
	gmp_printf("mp = %Zx\n", mp);

	RSA_KEY_clear(&pub,&pri);

	gmp_randclear(state);
	mpz_clear(m); mpz_clear(mp); mpz_clear(c);

}

void test_enc_dec_primitive_test()
{
	int i;
	int RSA_SIZE;
	mpz_t m, mp, c,mm;
	RSA_PUBKEY pub;
	RSA_PRIKEY pri;
	gmp_randstate_t state;

	mpz_init(m); mpz_init(mp); mpz_init(c); mpz_init(mm);
	gmp_randinit_default(state);

	RSA_SIZE = 2048;
	RSA_KEY_init(&pub, &pri);
	RSA_KEY_gen(&pub, &pri, 2048);
	
	gmp_printf("p = %Zx\n", pri.p);
	gmp_printf("q = %Zx\n", pri.q);
	gmp_printf("n = %Zx\n", pri.n);
	gmp_printf("e = %Zx\n", pri.e);
	gmp_printf("d = %Zx\n\n", pri.d);
	gmp_printf("dp = %Zx\n\n", pri.dp);
	gmp_printf("dq = %Zx\n\n", pri.dq);
	gmp_printf("qinv = %Zx\n\n", pri.qinv);
	gmp_printf("e = %Zx\n", pub.e);
	gmp_printf("n = %Zx\n\n", pub.n);

	// 메시지 선택
	mpz_urandomm(m, state, pri.n);
	//암호화
	RSA_enc_primitive(c, m, &pub);
	//mpz_powm(mp, m, pub.e, pub.n);
	//복호화
	mpz_powm(mm, c,  pri.d, pri.n);
	RSA_dec_primitive(mp, c, &pri);
	
	if (mpz_cmp(mp, mm))
		printf("fail\n");
	else
		printf("pass\n");

	gmp_printf("m  = %Zx\n", m);
	gmp_printf("c = %Zx\n", c);
	gmp_printf("mp = %Zx\n", mp);

	START_WATCH;
	for(i=0;i<50;i++) RSA_enc_primitive(c, m, &pub);
	STOP_WATCH;
	PRINT_TIME("enc pri");

	START_WATCH;
	for (i = 0; i<50; i++) RSA_dec_primitive(m, c, &pri);
	STOP_WATCH;
	PRINT_TIME("dec pri");

	pub.e->_mp_d[0] = pri.e->_mp_d[1] = 0x10003;
#undef USE_CRT
	START_WATCH;
	for (i = 0; i<50; i++) RSA_enc_primitive(c, m, &pub);
	STOP_WATCH;
	PRINT_TIME("enc mpz");
	
	START_WATCH;
	for (i = 0; i<50; i++) mpz_powm(mm, c, pri.d, pri.n);
	STOP_WATCH;
	PRINT_TIME("dec mpz");

	getchar();

	RSA_KEY_clear(&pub, &pri);

	gmp_randclear(state);
	mpz_clear(m); mpz_clear(mp); mpz_clear(c); mpz_clear(mm);
}

void RSA_OAEP_test()
{
	char *EM, *M, *TMP;
	int EM_len, M_len, TMP_len;
	char label[32];
	int label_len;
	char seed[32];
	int seed_len;

	RSA_PUBKEY pub;
	RSA_PRIKEY pri;

	RSA_KEY_init(&pub, &pri);
	RSA_KEY_gen(&pub, &pri, 2048);

	label_len = 32;
	seed_len = 32;
	
	M = "kkkkafdfdffsfdf";
	memcpy(label, "\x99", sizeof("\x99"));
	memcpy(seed, "\x69", sizeof("\x69"));
	M_len = strlen(M);
	EM_len = 256;
	EM = (unsigned char*)calloc(EM_len, 1);
	TMP = (unsigned char*)calloc(M_len, 1);

	// encoding
	//RSA_PKCS1_RSA2048_SHA256_OAEP_encode(EM, &EM_len, M, M_len, label, label_len, seed, seed_len);

	//decoing
	//RSA_PKCS1_RSA2048_SHA256_OAEP_decode(TMP, &TMP_len, EM, EM_len, label, label_len);

	START_WATCH;
	for (int i = 0; i < 50; i++)  RSA_RSA2048_SHA256_OAEP_enc(EM, &EM_len, M, M_len, label, label_len, &pub);
	STOP_WATCH;
	PRINT_TIME("enc pri");
	START_WATCH;
	for (int i = 0; i < 50; i++)  	RSA_RSA2048_SHA256_OAEP_dec(TMP, &TMP_len, EM, EM_len, label, label_len, &pri);
	STOP_WATCH;
	PRINT_TIME("dec pri");

	printf("M: %s\n", M);
	printf("TMP: %s\n", TMP);
	

	RSA_KEY_clear(&pub, &pri);

	free(EM);
	free(TMP);
}

void test_pss_encode()
{
	unsigned char M[256] = "RSA_PSS_ENCODE_TEST_MESSAGE";
	unsigned char Salt[256] = { 0, };
	unsigned char mp[256] = { 0, };
	unsigned char H[256] = { 0x7f, 0x41, 0xe9, 0xd6, 0x86, 0xf4, 0x70, 0xe5, 0x8d, 0x37, 0x34, 0xd6, 0xf5, 0x7e, 0x82, 0x37, 0x98, 0x0a, 0x95, 0xb1, 0xb8, 0xab, 0x6e, 0x4b, 0x74, 0x7d, 0x9b, 0xca, 0xe4, 0xde, 0x77, 0xd2, 0, };
	unsigned char H2[256] = { 0, };

	int           mp_len, Salt_len, H_len, M_len;
	int           i;

	unsigned char mHash[SHA256_DIGEST_VALUELEN] = { 0, };
	/******input*********/
	M_len = strlen(M);
	Salt_len = SHA256_DIGEST_VALUELEN;
	/******input*********/

	SHA256_Encrpyt(M, M_len, mHash);
	H_len = 32;

	if (Salt_len != H_len) return -1;

	memcpy(mp + 8, mHash, H_len);
	memcpy(mp + 8 + H_len, Salt, Salt_len);
	mp_len = (H_len << 1) + 8;
	SHA256_Encrpyt(mp, mp_len, H2);

	printf("M=");
	for (int i = 0; i < M_len; i++) printf("0x%x, ", M[i]);
	printf("\n\nSalt=");
	for (int i = 0; i < Salt_len; i++) printf("0x%x, ", Salt[i]);
	printf("\n\nmp=");
	for (int i = 0; i < mp_len; i++) printf("0x%x, ", mp[i]);
	printf("\n\nH2=");
	for (int i = 0; i < H_len; i++) printf("0x%x, ", H2[i]);
	printf("\n\n");

	for (int i = 0; i < H_len; i++) {
		if (H[i] != H[i]) {
			printf("Wrong!! H != H2\n\n");
			break;
		}
	}
	printf("Right!! H == H2\n\n");

}

void pss_test()
{
	unsigned char M[256] = "RSA_PSS_ENCODE_TEST_MESSAGE";
	unsigned char Salt[256] = { 0, };
	unsigned char *EM;
	int M_len = strlen(M);
	int Salt_len = 32;
	int EM_len = 256;

	EM = (unsigned char*)calloc(EM_len, 1);

	RSA_EMSA_PSS_encode(EM, EM_len, M, M_len, Salt, Salt_len);

	//for (int i = 0; i < EM_len; i++) printf("0x%x, ", EM[i]);

	RSA_EMSA_PSS_decode(EM, EM_len, M, M_len);

}

void main(void)
{
	//test_addsubmul();
	//gmp_speed_test();
	//test_sha256();
	//test_add_sub();
	//test_powm();
	//test_rsa_keygen();
	//test_enc_dec_primitive_test();
	//RSA_OAEP_test();
	//test_pss_encode();

	pss_test();
}
