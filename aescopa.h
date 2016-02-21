/* 16-byte key k, 16-byte nonce n, plaintext m, store encrypted at c.
   Store the 16-byte tag at the end of c. Length of the plaintext d (d*16bytes). */
void aescopa(unsigned char *c, const unsigned char *k, const unsigned char *n, const unsigned char *m, const unsigned int d);

