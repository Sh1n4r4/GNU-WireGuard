/*
   Copyright (C) 2026 Sh1n4r4.

   This file is part of the GNU Hurd.

   The GNU Hurd is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   The GNU Hurd is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with the GNU Hurd.  If not, see <https://www.gnu.org/licenses/>.

   SPDX-License-Identifier: GPL-2.0-or-later
*/

/* WireGuard Cryptographic Primitives */

#ifndef WIREGUARD_CRYPTO_H
#define WIREGUARD_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <gcrypt.h>

/* WireGuard uses 256-bit keys */
#define WG_KEY_LEN		32
#define WG_NONCE_LEN		12
#define WG_TAG_LEN		16	/* Poly1305 tag */
#define WG_HASH_LEN		32	/* BLAKE2s output */

/* ChaCha20-Poly1305 AEAD context */
struct chacha20poly1305_ctx
{
  gcry_cipher_hd_t chacha;
  gcry_mac_hd_t poly1305;
};

/* Curve25519 keypair */
struct curve25519_keypair
{
  uint8_t private_key[WG_KEY_LEN];
  uint8_t public_key[WG_KEY_LEN];
};

/* Initialize cryptographic library */
int wg_crypto_init (void);

/* Curve25519 operations */
int curve25519_generate_keypair (struct curve25519_keypair *keypair);
int curve25519_derive_shared_secret (const uint8_t *private_key,
				     const uint8_t *public_key,
				     uint8_t *shared_secret);
int curve25519_public_from_private (uint8_t *public_key,
				    const uint8_t *private_key);

/* ChaCha20-Poly1305 AEAD */
int chacha20poly1305_init (struct chacha20poly1305_ctx *ctx,
			   const uint8_t *key, size_t key_len);
int chacha20poly1305_encrypt (struct chacha20poly1305_ctx *ctx,
			      const uint8_t *nonce,
			      const uint8_t *aad, size_t aad_len,
			      const uint8_t *plaintext, size_t plaintext_len,
			      uint8_t *ciphertext, uint8_t *tag);
int chacha20poly1305_decrypt (struct chacha20poly1305_ctx *ctx,
			      const uint8_t *nonce,
			      const uint8_t *aad, size_t aad_len,
			      const uint8_t *ciphertext, size_t ciphertext_len,
			      const uint8_t *tag,
			      uint8_t *plaintext);
void chacha20poly1305_close (struct chacha20poly1305_ctx *ctx);

/* BLAKE2s hashing */
int blake2s_hash (uint8_t *output, size_t outlen,
		  const uint8_t *data, size_t data_len);
int blake2s_hmac (uint8_t *output, size_t outlen,
		  const uint8_t *key, size_t key_len,
		  const uint8_t *data, size_t data_len);

/* Key derivation function (KDF) using BLAKE2s */
void wg_kdf (uint8_t *t1, uint8_t *t2, uint8_t *t3,
	     const uint8_t *secret, size_t secret_len,
	     const uint8_t *chain_key, size_t chain_key_len);

/* SIPHASH-24 for MAC1 */
int siphash24 (const uint8_t *key, const uint8_t *data, size_t data_len,
	       uint8_t *output);

/* Free cryptographic resources */
void wg_crypto_cleanup (void);

#endif /* WIREGUARD_CRYPTO_H */
