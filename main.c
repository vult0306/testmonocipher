#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include "monocypher.h"
#include "monocypher-ed25519.h"

void xed25519_sign(uint8_t signature[64],
                   const uint8_t secret_key[32],
                   const uint8_t random[64],
                   const uint8_t *message, size_t message_size)
{
	static const uint8_t zero   [32] = {0};
	static const uint8_t minus_1[32] = {
		0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	};
	static const uint8_t prefix[32] = {
		0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	};

	/* Key pair (a, A) */
	uint8_t A[32];  /* XEdDSA public key  */
	uint8_t a[32];  /* XEdDSA private key */
	crypto_eddsa_trim_scalar(a, secret_key);
	crypto_eddsa_scalarbase(A, a);
	int is_negative = A[31] & 0x80; /* Retrieve sign bit */
	A[31] &= 0x7f;                  /* Clear sign bit    */
	if (is_negative) {
		/* a = -a */
		crypto_eddsa_mul_add(a, a, minus_1, zero);
	}

	/* Secret nonce r */
	uint8_t r[64];
	crypto_sha512_ctx ctx;
	crypto_sha512_init  (&ctx);
	crypto_sha512_update(&ctx, prefix , 32);
	crypto_sha512_update(&ctx, a      , 32);
	crypto_sha512_update(&ctx, message, message_size);
	crypto_sha512_update(&ctx, random , 64);
	crypto_sha512_final (&ctx, r);
	crypto_eddsa_reduce(r, r);

	/* First half of the signature R */
	uint8_t R[32];
	crypto_eddsa_scalarbase(R, r);

	/* hash(R || A || M) */
	uint8_t H[64];
	crypto_sha512_init  (&ctx);
	crypto_sha512_update(&ctx, R      , 32);
	crypto_sha512_update(&ctx, A      , 32);
	crypto_sha512_update(&ctx, message, message_size);
	crypto_sha512_final (&ctx, H);
	crypto_eddsa_reduce(H, H);

	/* Signature */
	memcpy(signature, R, 32);
	crypto_eddsa_mul_add(signature + 32, a, H, r);

	/* Wipe secrets (A, R, and H are not secret) */
	crypto_wipe(a, 32);
	crypto_wipe(r, 32);
}

int xed25519_verify(const uint8_t signature[64],
                    const uint8_t public_key[32],
                    const uint8_t *message, size_t message_size)
{
	/* Convert X25519 key to EdDSA */
	uint8_t A[32];
	crypto_x25519_to_eddsa(A, public_key);

	/* hash(R || A || M) */
	uint8_t H[64];
	crypto_sha512_ctx ctx;
	crypto_sha512_init  (&ctx);
	crypto_sha512_update(&ctx, signature, 32);
	crypto_sha512_update(&ctx, A        , 32);
	crypto_sha512_update(&ctx, message  , message_size);
	crypto_sha512_final (&ctx, H);
	crypto_eddsa_reduce(H, H);

	/* Check signature */
	return crypto_eddsa_check_equation(signature, A, H);
}

int main(void) {
    uint8_t signature[64] = {0};
    uint8_t random[64];
    uint8_t secret_key[32];
    uint8_t public_key[32];
    memset(secret_key, 1, sizeof(secret_key));
    memset(random, 2, sizeof(random));
    crypto_x25519_public_key(public_key, secret_key);
    uint8_t message[3] = {1,2,3};
    xed25519_sign(signature, secret_key,random,message, sizeof(message));
    printf("\nsignature:\n");
    for (int i=0; i<sizeof(signature); i++)
        printf("0x%.02x,",signature[i]);
    printf("\nsecret_key:\n");
    for (int i=0; i<sizeof(secret_key); i++)
        printf("0x%.02x,",secret_key[i]);
    printf("\npublic_key:\n");
    for (int i=0; i<sizeof(public_key); i++)
        printf("0x%.02x,",public_key[i]);

    int result = xed25519_verify(signature, public_key, message, sizeof(message));
    printf("\nresult: %d\n",result);
    return 0;
}

