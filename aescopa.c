/* Course assignment:
AES-COPA
Test vectors not included. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "aescopa.h"
#include "aes128e.h"

#define NUM_BYTES 16

void multiplyby2(unsigned char *ct);

void multiplyby3(unsigned char *ct);

void multiplyby7(unsigned char *ct);

void pmac1(unsigned char *v, const unsigned char *n, const unsigned char *k);

void getl(unsigned char *l, const unsigned char *k);

void encrypt(unsigned char *v, const unsigned char *m, unsigned char *c, unsigned char *s, const unsigned char *k, const unsigned int d);

/* Under the 16-byte key at k and the 16-byte nonce at n, encrypt the plaintext at m and store it at c.
   Store the 16-byte tag in the end of c. The length of the plaintext is a multiple of 16 bytes given at d (e.g., 
   d = 2 for a 32-byte m). */
void aescopa(unsigned char *c, const unsigned char *k, const unsigned char *n, const unsigned char *m, const unsigned int d) {

	unsigned char v[NUM_BYTES];
	unsigned char s[NUM_BYTES];
	unsigned char sigma[NUM_BYTES];
	unsigned char l[NUM_BYTES];
	unsigned char aes1[NUM_BYTES];
	unsigned char aes2[NUM_BYTES];
	unsigned char t[NUM_BYTES];

	// V <- PMAC1'(N)
	pmac1(v, n, k);

	// (C,S) <- ENCRYPT(V,M)
	encrypt(v, m, c, s, k, d);

	// Sigma <- M[1] xor M[2] xor ... M[d]
	// Initial sigma == M[1]
	memcpy(sigma, m, NUM_BYTES);

	for (int i = 1; i < d; i++) {
		for (int j = 0; j < NUM_BYTES; j++) {
			sigma[j] = sigma[j] ^ m[i*NUM_BYTES+j];
		}
	}

	// Sigma xor (2^(d-1)*3^2*L)
	// 3^2 L
	getl(l, k);
	multiplyby3(l);
	multiplyby3(l);

	// 2^(d-1) (3^2 L)
	for (int i = 0; i < d-1; i++) {
		multiplyby2(l);
	}

	// Sigma xor ...
	for (int i = 0; i < NUM_BYTES; i++) {
		sigma[i] = sigma[i] ^ l[i];
	}

	// E_k(sigma xor ...) = aes1
	aes128e(aes1, sigma, k);

	// aes1 xor S
	for (int i = 0; i < NUM_BYTES; i++) {
		aes1[i] = aes1[i] ^ s[i];
	}

	// E_k(aes1 xor S) = aes2
	aes128e(aes2, aes1, k);

	// 7L
	getl(l, k);
	multiplyby7(l);

	// 2^d*7L
	for (int i = 0; i < d; i++) {
		multiplyby2(l);
	}

	// T = aes2 xor 2^d*7L
	for (int i = 0; i < NUM_BYTES; i++) {
		t[i] = aes2[i] ^ l[i];
	}

	// Copy T to the end of C.
	memcpy((c+d*NUM_BYTES), t, NUM_BYTES);
	
}

// x*a(x) (multiplication by 2). ct: pointer to block. Here assumed to always be 128 bits in length, as it should be.
void multiplyby2(unsigned char *ct) {

	int carryprev = 0;
	int carrycurr = 0;

	// Start from the rightmost byte.
	for (int i = NUM_BYTES - 1; i >= 0; i--) {
		carrycurr = (*(ct+i) & (0x01 << 7));
		*(ct+i) = *(ct+i) << 1;

		if (carryprev != 0) {
			*(ct+i) = *(ct+i) | 0x01;
		}
		carryprev = carrycurr;
	}

	// If a_127 == 1, xor rightmost byte with with 0x87
	if (carryprev != 0) {
		*(ct+NUM_BYTES - 1) = *(ct+NUM_BYTES-1) ^ 0x87;
	}
}

// Takes pointer to the 16-byte char array to be multiplied by 3 in GF128
void multiplyby3(unsigned char *ct) {

	unsigned char temp[NUM_BYTES];

	memcpy(temp, ct, NUM_BYTES);

	// multiply by 2 first
	multiplyby2(ct);

	// XOR the original to the multiplied.
	for (int i = 0; i < NUM_BYTES; i++) {
		ct[i] = ct[i] ^ temp[i];
	}

}

// Multiply by 7 in GF128.
// Param: pointer to the 16-byte block to be modified.
void multiplyby7(unsigned char *ct) {
	
	unsigned char temp[NUM_BYTES];

	memcpy(temp, ct, NUM_BYTES);

	// (x+1)a(x)
	multiplyby3(temp);

	// x^2*a(x)
	multiplyby2(ct);
	multiplyby2(ct);

	// x^2*a(x) + (x+1)*a(x)
	for (int i = 0; i < NUM_BYTES; i++) {
		ct[i] = ct[i] ^ temp[i];
	}
}

// Helper function to generate L=E_k(0) when needed.
void getl(unsigned char *l, const unsigned char *k) {

	unsigned char temp[NUM_BYTES] = {0x00};
	aes128e(l, temp, k);

}

// PMAC1'(N)
// Param: pointers to V, n (nonce) and k (key)
// Modifies v.
void pmac1(unsigned char *v, const unsigned char *n, const unsigned char *k) {

	unsigned char delta0[NUM_BYTES];
	
	getl(delta0, k);

	// delta0 <- 3^3 * L
	for (int j = 0; j < 3; j++) {
		
		multiplyby3(delta0);

	}

	// 3*delta0
	multiplyby3(delta0);

	// N xor 3*delta0
	for (int i = 0; i < NUM_BYTES; i++) {
		delta0[i] = delta0[i] ^ n[i];
	}

	// V = E_k(N xor 3*delta0)
	aes128e(v, delta0, k);
}


// (C,S) <- ENCRYPT(V,M)
// Params: pointers to v, m, c, s, key k, length d
void encrypt(unsigned char *v, const unsigned char *m, unsigned char *c, unsigned char *s, const unsigned char *k, const unsigned int d) {

	unsigned char delta0[NUM_BYTES];
	unsigned char delta1[NUM_BYTES];
	unsigned char l[NUM_BYTES];
	// Holder for the current block.
	unsigned char tempm[NUM_BYTES];
	unsigned char tempm2[NUM_BYTES];
	unsigned char tempv[NUM_BYTES];
	unsigned char v1[NUM_BYTES];

	// delta0 <- 3L
	getl(delta0, k);
	multiplyby3(delta0);

	// delta1 <- 2L
	getl(delta1, k);
	multiplyby2(delta1);

	// V[0] <- V xor L
	getl(l, k);
	
	for (int i = 0; i < NUM_BYTES; i++) {
		v[i] = v[i] ^ l[i];
	}

	// One 128-bit block at a time.
	for (int i = 0; i < d; i++) {

		// Copy the block to the temp holder.
		memcpy(tempm, m+i*NUM_BYTES, NUM_BYTES);

		// M[i] xor delta0
		for (int j = 0; j < NUM_BYTES; j++) {
			tempm[j] = tempm[j] ^ delta0[j];
		}

		// E_k(M[i] xor delta0)
		aes128e(tempm2, tempm, k);

		// V[i] <- E_k(M[i] xor delta0) xor V[i-1]
		for (int j = 0; j < NUM_BYTES; j++) {
			v1[j] = tempm2[j] ^ v[j];
		}
		
		// E_k(V[i])
		aes128e(tempv, v1, k);

		// C[i] = E_k(V[i]) xor delta1
		for (int j = 0; j < NUM_BYTES; j++) {
			c[i*NUM_BYTES+j] = tempv[j] ^ delta1[j];
		}

		// Set up next round:
		// 2*delta0, 2*delta1, V[i-1] = V[i]
		multiplyby2(delta0);
		multiplyby2(delta1);
		memcpy(v, v1, NUM_BYTES);
	}

	// Copy the final value of v[i] to s
	memcpy(s, v1, NUM_BYTES);

}
