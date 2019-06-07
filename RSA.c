#include <string.h>
#include "rsa.h"

void dumpString(unsigned char *s, int arraySize) {

	printf("배열의 바이트 수: %d\n", arraySize);
	printf("0x");
	for (size_t i = 0; i < arraySize; i++)
		printf("%02x", s[i], *(s + i));
	printf("\n");
}

void RSA_KEY_init(RSA_PUBKEY *pub, RSA_PRIKEY *pri)
{
	// pubkey init
	mpz_init(pub->e);
	mpz_init(pub->n);
	pub->RSA_SIZE = 0;

	// prikey init
	mpz_init(pri->e);
	mpz_init(pri->n);
	mpz_init(pri->p);
	mpz_init(pri->q);
	mpz_init(pri->d);

#ifdef USE_CRT
	mpz_init(pri->dp);
	mpz_init(pri->dq);
	mpz_init(pri->qinv);
#endif
	pri->RSA_SIZE = 0;
}

int RSA_KEY_gen(RSA_PUBKEY *pub, RSA_PRIKEY *pri, int RSA_SIZE)
{
	int             mr_test;
	mpz_t           tmp;
	gmp_randstate_t state;

	if ( !((RSA_SIZE == 2048) || (RSA_SIZE == 3072)) )
		return -1;

	mpz_init(tmp);
	gmp_randinit_default(state);

	pri->RSA_SIZE = RSA_SIZE;

	// pri e
	mpz_set_ui(pri->e, 0x10001);
	//pri->e->_mp_d[0] = 0x10001;
	//pri->e->_mp_size = 1;

	// pri p
	while(mpz_size(pri->p) != 32)
		 mpz_urandomb(pri->p, state, (RSA_SIZE >> 1));
	while (1)
	{		
		pri->p->_mp_d[0]  = pri->p->_mp_d[0]  & 0xfffffffe;
		pri->p->_mp_d[31] = pri->p->_mp_d[31] | 0x80000000;
		mpz_gcd(tmp, pri->e, pri->p);

		if ((tmp->_mp_d[0]==1) && (tmp->_mp_size==1))
		{
			pri->p->_mp_d[0] = pri->p->_mp_d[0] | 1;
			if (mpz_probab_prime_p(pri->p, 56))
				break;
		}
		mpz_add_ui(pri->p, pri->p, 2);
		if (mpz_size(pri->p) > 32) {
			while (mpz_size(pri->p) != 32)
				mpz_urandomb(pri->p, state, (RSA_SIZE >> 1));
		}
	}

	// pri q
	while (mpz_size(pri->q) != 32)
		mpz_urandomb(pri->q, state, (RSA_SIZE >> 1));
	while (1)
	{
		pri->q->_mp_d[0]  = pri->q->_mp_d[0] & 0xfffffffe;
		pri->q->_mp_d[31] = pri->q->_mp_d[31] | 0x80000000;
		mpz_gcd(tmp, pri->e, pri->q);

		if ((tmp->_mp_d[0] == 1) && (tmp->_mp_size == 1))
		{
			pri->q->_mp_d[0] = pri->q->_mp_d[0] | 1;
			if (mpz_probab_prime_p(pri->q, 56))
				break;
		}
		mpz_add_ui(pri->q, pri->q, 2);
		if (mpz_size(pri->q) > 32) {
			while (mpz_size(pri->q) != 32)
				mpz_urandomb(pri->q, state, (RSA_SIZE >> 1));
		}
	}
	// pri n
	mpz_mul(pri->n, pri->p, pri->q);

	// pri d
	pri->p->_mp_d[0] = pri->p->_mp_d[0] & 0xfffffffe;
	pri->q->_mp_d[0] = pri->q->_mp_d[0] & 0xfffffffe;
	mpz_mul(tmp, pri->p, pri->q);
	pri->p->_mp_d[0] = pri->p->_mp_d[0] | 1;
	pri->q->_mp_d[0] = pri->q->_mp_d[0] | 1;
	mpz_invert(pri->d, pri->e, tmp);

#ifdef USE_CRT
	//dp
	pri->p->_mp_d[0] = pri->p->_mp_d[0] & 0xfffffffe;
	mpz_mod(pri->dp, pri->d, pri->p);
	pri->p->_mp_d[0] = pri->p->_mp_d[0] | 1;

	//dq
	pri->q->_mp_d[0] = pri->q->_mp_d[0] & 0xfffffffe;
	mpz_mod(pri->dq, pri->d, pri->q);
	pri->q->_mp_d[0] = pri->q->_mp_d[0] | 1;

	//qinv
	mpz_invert(pri->qinv, pri->p, pri->q);
#endif
	
	// pub e
	mpz_set(pub->e, pri->e);
	// pub n
	mpz_set(pub->n, pri->n);
	pub->RSA_SIZE = pri->RSA_SIZE;
	
	mpz_clear(tmp);
	gmp_randclear(state);
}

void RSA_KEY_clear(RSA_PUBKEY *pub, RSA_PRIKEY *pri) 
{

	memset(pub->e->_mp_d, 0, (mpz_size(pub->e) << 2));
	memset(pub->n->_mp_d, 0, (mpz_size(pub->n) << 2));

	memset(pri->e->_mp_d, 0, (mpz_size(pri->e) << 2));
	memset(pri->n->_mp_d, 0, (mpz_size(pri->n) << 2));
	memset(pri->p->_mp_d, 0, (mpz_size(pri->p) << 2));
	memset(pri->q->_mp_d, 0, (mpz_size(pri->q) << 2));
	memset(pri->d->_mp_d, 0, (mpz_size(pri->d) << 2));

	// pubkey clear
	mpz_clear(pub->e);
	mpz_clear(pub->n);
	pub->RSA_SIZE = 0;

	// prikey clear
	mpz_clear(pri->e);
	mpz_clear(pri->n);
	mpz_clear(pri->p);
	mpz_clear(pri->q);
	mpz_clear(pri->d);

#ifdef USE_CRT
	mpz_clear(pri->dp);
	mpz_clear(pri->dq);
	mpz_clear(pri->qinv);
#endif
	pri->RSA_SIZE = 0;

}

void RSA_enc_primitive(mpz_t c, mpz_t m, RSA_PUBKEY *pub)
{
	// m^e mod n = c

	if ((pub->e->_mp_size==1) && (pub->e->_mp_d[0]==0x10001)) {
		//e = 2^16 + 1
		mpz_mul(c, m, m); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, c); mpz_mod(c, c, pub->n);
		mpz_mul(c, c, m); mpz_mod(c, c, pub->n);
	}
	else {
		mpz_powm(c, m, pub->e, pub->n);
	}
}

void RSA_dec_primitive(mpz_t m, mpz_t c, RSA_PRIKEY *pri)
{
	// c^d mod n = m
#ifdef USE_CRT
	//garner crt
	mpz_t x, y;

	mpz_init(x); mpz_init(y);

	mpz_mod(x, c, pri->p);
	mpz_powm(x, x, pri->dp, pri->p);
	mpz_mod(y, c, pri->q);
	mpz_powm(y, y, pri->dq, pri->q);

	mpz_sub(y, y, x);         mpz_mod(y, y, pri->n);
	mpz_mul(y, y, pri->qinv); mpz_mod(y, y, pri->n);
	mpz_mul(y, y, pri->p);    mpz_mod(y, y, pri->n);
	mpz_add(y, y, x);         mpz_mod(m, y, pri->n);

	mpz_clear(x); mpz_clear(y);
#else
	mpz_powm(m, c, pri->d, pri->n);
#endif
}


int RSA_PKCS1_SHA256_MGF(unsigned char *mask, int masklen, unsigned char *mgfseed, int mgfseedlen) {
	int           hlen, looplen;
	unsigned int  counter;
	unsigned char *T, *tmgf;
	
	hlen = SHA256_DIGEST_VALUELEN;

	looplen = (masklen / hlen) + ((masklen%hlen) != 0);

	//masklen이 int형이므로 2^32를 넘어갈 수가 없음. 그래서 생략됨

	T =    (unsigned char*)calloc(1, (looplen*hlen) + 8);
	tmgf = (unsigned char*)calloc(1, (mgfseedlen + 4) + 8);
	memcpy(tmgf, mgfseed, mgfseedlen);

	for (counter = 0; counter < (unsigned long)looplen; counter++) {
		tmgf[mgfseedlen] = (unsigned char)(counter >> 24);
		tmgf[mgfseedlen + 1] = (unsigned char)((counter >> 16) & 0xff);
		tmgf[mgfseedlen + 2] = (unsigned char)((counter >> 8) & 0xff);
		tmgf[mgfseedlen + 3] = (unsigned char)(counter & 0xff);
		SHA256_Encrpyt(tmgf, mgfseedlen + 4, &T[counter*hlen]);
	}

	
	memcpy(mask, T, masklen);
	free(T);
	free(tmgf);

	return 0;
}


int RSA_PKCS1_RSA2048_SHA256_OAEP_encode(unsigned char *EM, int EM_len,
									  	 unsigned char *M, int M_len,
										 unsigned char *L, int L_len,
										 unsigned char *S, int S_len)
{
	unsigned char *LHash;
	unsigned char *DB;
	unsigned char *DBmask, *maskedDB;
	unsigned char *Smask, *maskedS;
	int h_len, DB_len;

	// 1. EM_LEN=?256, M_len<=?(256-64-2), S_len=?SHA256_DIGEST_VALUELEN 
	if (EM_len != 256 && M_len > (256 - 64 - 2) && S_len != SHA256_DIGEST_VALUELEN)
	{
		printf("S_len: %d\n", S_len);
		printf("len error\n");  return -1;
	}
	h_len = 32;
	DB_len = 256 - S_len - 1;
	LHash = (unsigned char*)calloc(h_len, 1);
	DB = (unsigned char*)calloc(DB_len, 1);
	DBmask = (unsigned char*)calloc(DB_len, 1);
	maskedDB = (unsigned char*)calloc(DB_len, 1);
	Smask = (unsigned char*)calloc(S_len, 1);
	maskedS = (unsigned char*)calloc(S_len, 1);


	// 2. EM[0]=0
	EM[0] = '\x00';
	SHA256_Encrpyt(L, L_len, LHash);
	// 3. DB = LHash || PS || 0x01 || M
	memcpy(DB, LHash, h_len);
	DB[DB_len - M_len - 1] = '\x01';
	memcpy(DB + DB_len - M_len, M, M_len);

	// 4. EM = EM = 00 || maskedseed || maskedDB
	  // 4.1 maskedDB = DB ^ mgf(seed)
	RSA_PKCS1_SHA256_MGF(DBmask, DB_len, S, S_len);
	for (int i = 0; i < DB_len; i++) 
		maskedDB[i] = DB[i] ^ DBmask[i];

	  // 4.2 maskedseed = seed ^ mgf(maskedDB) 
	RSA_PKCS1_SHA256_MGF(Smask, S_len, maskedDB, DB_len);
	for (int i = 0; i < S_len; i++)
		maskedS[i] = S[i] ^ Smask[i];

	memcpy(EM + 1, maskedS, S_len);
	memcpy(EM + 1 + S_len, maskedDB, DB_len);



	free(LHash); free(DB); 
	free(DBmask); free(maskedDB);
	free(Smask); free(maskedS);

	return 0;
}


int RSA_PKCS1_RSA2048_SHA256_OAEP_decode(unsigned char *M, int *M_len,
										 unsigned char *EM, int EM_len,
										 unsigned char *L, int L_len)
{
	unsigned char *LHash, *LHash2;
	unsigned char *DB;
	unsigned char *S;
	unsigned char *DBmask, *maskedDB;
	unsigned char *Smask, *maskedS;
	int h_len, DB_len, S_len;
	int i;

	S_len = 32;
	h_len = 32;
	DB_len = 256 - S_len - 1;

	// 1. EM_LEN=?256, M_len<=?(256-64-2), S_len=?SHA256_DIGEST_VALUELEN 
	if (EM_len != 256 && M_len > (256 - 64 - 2) && S_len != SHA256_DIGEST_VALUELEN)
		return -1;

	// 2. EM = 00 || maskedseed || maskedDB, EM[0]=?0
	if (EM[0] != '\x00')
		return -1;
	
	LHash = (unsigned char*)calloc(h_len, 1);
	LHash2 = (unsigned char*)calloc(h_len, 1);
	DB = (unsigned char*)calloc(DB_len, 1);
	S = (unsigned char*)calloc(S_len, 1);
	DBmask = (unsigned char*)calloc(DB_len, 1);
	maskedDB = (unsigned char*)calloc(DB_len, 1);
	Smask = (unsigned char*)calloc(S_len, 1);
	maskedS = (unsigned char*)calloc(S_len, 1);


	SHA256_Encrpyt(L, L_len, LHash);

	memcpy(maskedS, EM + 1, S_len);
	memcpy(maskedDB, EM + 1 + S_len, DB_len);

	// 3. seed = maskedseed ^ mgf(maskedDB) 
	RSA_PKCS1_SHA256_MGF(Smask, S_len, maskedDB, DB_len);
	for (int i = 0; i < S_len; i++)
		S[i] = maskedS[i] ^ Smask[i];

	// 4. DB = maskedDB ^ mgf(seed)
	RSA_PKCS1_SHA256_MGF(DBmask, DB_len, S, S_len);
	for (int i = 0; i < DB_len; i++)
		DB[i] = maskedDB[i] ^ DBmask[i];

	// 5. DB = LHash || PS || 0x01 || M
	  //5.1 LHash=?Hash(Label)
	memcpy(LHash2, DB, h_len);
	if (memcmp(LHash, LHash2, h_len))
		return -1;
	  //5.2 DB[32] => 0 or 1
	for (i = h_len; i < DB_len; i++) {
		if (DB[i] != '\x00')	break;
	}
	if (i >= DB_len) 
		return -1;
	if (DB[i] != '\0x01')
		//return -1;
	  //5.3 M 복사
	*M_len = DB_len - i -1;
	memcpy(M, DB + i + 1, *M_len);
	memset(M + *M_len, '\x00', 1);

	free(LHash); free(LHash2);
	free(DB); free(S);
	free(DBmask); free(maskedDB);
	free(Smask); free(maskedS);
	return 0;
}

int mpz_msb_bit_scan(const mpz_t a) 
{ 
	int i = 31, size; size = a->_mp_size - 1; 
	while ((i >= 0) && !(a->_mp_d[size] & (0x1 << i))) i--; 
	if (i < 0) return -1; 
	return ((size << 5) + i + 1); 
}

int mpz2ostr(unsigned char *ostr, int *ostrlen, const mpz_t a) 
{
	int i, bytelen;
	if ((a == 0) || (ostr == 0)) return -1; 
	if (a->_mp_size == 0) { *ostrlen = 0; return 0; }
	*ostrlen = (mpz_msb_bit_scan(a) + 7) >> 3; 
	bytelen = *ostrlen - 1; 
	for (i = 0; i < *ostrlen; i++) { 
		ostr[i] = (a->_mp_d[(bytelen - i) >> 2] >> (((bytelen - i) & 0x3) << 3)) & 0xff; 
	}
	return 0;
}
int ostr2mpz(mpz_t a, const unsigned char *ostr, const int ostrlen) {
	int i, bytelen;
	if (ostrlen == 0) { a->_mp_size = 0; return 0; } if ((a == 0) || (ostr == 0)) return -1; bytelen = ostrlen - 1; a->_mp_size = (ostrlen + 3) >> 2;
	if (a->_mp_alloc < a->_mp_size) mpz_realloc2(a, (a->_mp_size << 5)); memset((unsigned int *)a->_mp_d, 0, (a->_mp_size << 2)); for (i = bytelen; i >= 0; i--) { a->_mp_d[(bytelen - i) >> 2] |= ((ostr[i]) << (((bytelen - i) & 0x3) << 3)); }
	return 0;
}


int RSA_RSA2048_SHA256_OAEP_enc(unsigned char *C, int *C_len, unsigned char *M, int M_len, unsigned char *L, int L_len, RSA_PUBKEY *pub) 
{ 

	//1. EM, SEED  변수 선언
	unsigned char *EM;
	unsigned char *SEED;
	int EM_len, S_len, H_len;
	mpz_t S, em, c;
	gmp_randstate_t state;

	mpz_init(S); mpz_init(em); mpz_init(c);
	gmp_randinit_default(state);

	EM_len = 256;
	S_len = SHA256_DIGEST_VALUELEN;
	H_len = SHA256_DIGEST_VALUELEN;
	EM = (unsigned char *)calloc(EM_len, 1);
	SEED = (unsigned char *)calloc(S_len, 1);
	//2. SEED 생성 = urandomb(SEED,state,(H_LEN<<3))
	mpz_urandomb(S, state, (H_len << 3));
	//3. mpz2ostr(S,S_LEN,SEED)
	mpz2ostr(SEED, &S_len, S);
	//4. RSA_PKCS1_RSA2048_SHA256_OAEP_encode(EM, EM_len,M,M_len,L, L_len,S,S_len);      //인코딩 실패시 에러
	if(RSA_PKCS1_RSA2048_SHA256_OAEP_encode(EM, EM_len, M, M_len, L, L_len, SEED, S_len) == -1) return -1;
	//5. ostr2mpz(em,EM,EM_LEN);
	ostr2mpz(em, EM, EM_len);
	//6. RSA_enc_primitive(c, em, pub)
	RSA_enc_primitive(c, em, pub);
	//7. mpz2ostr(C,C_LEN,c)
	mpz2ostr(C, C_len, c);

	mpz_clear(S); mpz_clear(em); mpz_clear(c);
	free(EM); free(SEED);

	return 0;
}

int RSA_RSA2048_SHA256_OAEP_dec(unsigned char *M, int *M_len, unsigned char *C, int C_len, unsigned char *L, int L_len, RSA_PRIKEY *pri) 
{ 
	//1. EM 등  변수 선언
	unsigned char *EM;
	mpz_t em, c;
	int EM_len;

	mpz_init(em);	mpz_init(c);

	EM_len = 256;
	EM = (unsigned char*)calloc(EM_len, 1);
	//2. ostr2mpz(c,C,C_LEN);
	ostr2mpz(c, C, C_len);
	//3. RSA_dec_primitive(em,c,pri)
	RSA_dec_primitive(em, c, pri);
	//4. mpz2ostr(EM,EM_LEN,em)
	mpz2ostr(EM + 1, &EM_len, em);
	EM_len++;
	//5. RSA_PKCS1_RSA2048_SHA256_OAEP_decode(M, M_len, EM, EM_len,L, L_len);    // 실패시 에러
	if (RSA_PKCS1_RSA2048_SHA256_OAEP_decode(M, M_len, EM, EM_len, L, L_len) != -1)
		return -1;

	mpz_clear(em); mpz_clear(c);
	free(EM);

	return 0;
}

//입력 : EM_len, M, M_len, Salt, Salt_len//출력 : EM

int RSA_EMSA_PSS_encode(unsigned char *EM, int EM_len, unsigned char *M, int M_len, unsigned char *Salt, int Salt_len)
{
	//unsigned char M[256] = "RSA_PSS_ENCODE_TEST_MESSAGE";
	//unsigned char Salt[256] = { 0, };
	//unsigned char mp[256] = { 0, };
	//unsigned char H[256] = { 0x7f, 0x41, 0xe9, 0xd6, 0x86, 0xf4, 0x70, 0xe5, 0x8d, 0x37, 0x34, 0xd6, 0xf5, 0x7e, 0x82, 0x37, 0x98, 0x0a, 0x95, 0xb1, 0xb8, 0xab, 0x6e, 0x4b, 0x74, 0x7d, 0x9b, 0xca, 0xe4, 0xde, 0x77, 0xd2, 0, };
	//unsigned char H2[256] = { 0, };
	unsigned char *mp, *DB, *H, *Padding, *DBmask, *maskedDB;

	int           mp_len, H_len, DB_len, P_len;
	int           i;

	unsigned char mHash[SHA256_DIGEST_VALUELEN] = { 0, };

	SHA256_Encrpyt(M, M_len, mHash);
	H_len = 32;

	if (Salt_len != H_len) return -1;
	if (EM_len < H_len + Salt_len + 2) return -1;

	mp_len = (H_len << 1) + 8;
	mp = (unsigned char*)calloc(mp_len, 1);
	memcpy(mp + 8, mHash, H_len);
	memcpy(mp + 8 + H_len, Salt, Salt_len);

	H = (unsigned char*)calloc(H_len, 1);
	SHA256_Encrpyt(mp, mp_len, H);

	P_len = EM_len - (H_len << 1) - 2;
	Padding = (unsigned char*)calloc(P_len, 1);

	DB_len = EM_len - H_len - 1;
	DB = (unsigned char*)calloc(DB_len, 1);
	memcpy(DB, Padding, P_len);
	DB[P_len] = '\x01';
	memcpy(DB + P_len + 1, Salt, Salt_len);

	DBmask = (unsigned char*)calloc(DB_len, 1);
	RSA_PKCS1_SHA256_MGF(DBmask, DB_len, H, H_len);

	maskedDB = (unsigned char*)calloc(DB_len, 1);
	for (int i = 0; i < DB_len; i++)
		maskedDB[i] = DB[i] ^ DBmask[i];

	maskedDB[0] &= 0x7f;

	memcpy(EM, maskedDB, DB_len);
	memcpy(EM + DB_len, H, H_len);
	EM[DB_len + H_len] = 0xbc;


	free(mp); free(DB); free(H); free(Padding); free(DBmask); free(maskedDB);

	
}
//입력 : EM, EM_len, M, M_len//출력 : T/F

int RSA_EMSA_PSS_decode(unsigned char *EM, int EM_len, unsigned char *M, int M_len)
{
	unsigned char *DB, *maskedDB, *DBmask, *Salt, *H ,*mHash, *mp, *H2;

	int DB_len, mp_len, H_len, Salt_len, P_len;

	H_len = 32;
	mp_len = (H_len << 1) + 8;
	Salt_len = 32;
	if (EM_len < H_len + Salt_len + 2) return -1;
	DB_len = EM_len - H_len - 1;

	if (EM[0] & 0x80 != 0) return -1;
	if (EM[DB_len + H_len] != 0xbc) return -1;
	
	H = (unsigned char*)calloc(H_len, 1);
	memcpy(H, EM + DB_len, H_len);

	maskedDB = (unsigned char*)calloc(DB_len, 1);
	memcpy(maskedDB, EM, DB_len);

	DBmask = (unsigned char*)calloc(DB_len, 1);
	RSA_PKCS1_SHA256_MGF(DBmask, DB_len, H, H_len);

	DB = (unsigned char*)calloc(DB_len, 1);

	for (int i = 0; i < DB_len; i++)
		DB[i] = maskedDB[i] ^ DBmask[i];

	P_len = EM_len - (H_len << 1) - 2;

	Salt = (unsigned char*)calloc(Salt_len, 1);
	memcpy(Salt, DB + P_len + 1, Salt_len);

	mHash = (unsigned char*)calloc(H_len, 1);
	SHA256_Encrpyt(M, M_len, mHash);

	mp = (unsigned char*)calloc(mp_len, 1);
	memcpy(mp + 8, mHash, H_len);
	memcpy(mp + 8 + H_len, Salt, Salt_len);

	H2 = (unsigned char*)calloc(H_len, 1);
	SHA256_Encrpyt(mp, mp_len, H2);
	
	for (int i = 0; i < H_len; i++) {
		if (H[i] != H2[i]) {
			printf("Wrong!! H != H2\n\n");
			break;
		}
	}
	printf("Right!! H == H2\n\n");

	free(mp); free(DB); free(H); free(DBmask); free(maskedDB); free(mHash); free(H2); free(Salt);
}


