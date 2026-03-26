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

/* WireGuard Cryptographic Primitives Implementation using libgcrypt */

#include "wg-crypto.h"

#include <string.h>
#include <errno.h>
#include <error.h>
#include <lwip-hurd.h>

/* Check if libgcrypt version is sufficient */
#define MIN_GCRYPT_VERSION "1.8.0"

/* WireGuard constants */
#define WG_LABEL "WireGuard Initiation\0"
#define WG_LABEL_LEN 23

static int crypto_initialized = 0;

/*
 * Initialize cryptographic library
 */
int
wg_crypto_init (void)
{
  if (!crypto_initialized)
    {
      /* Check libgcrypt version */
      if (!gcry_check_version (MIN_GCRYPT_VERSION))
	{
	  error (0, 0, "libgcrypt version mismatch (minimum %s required)",
		 MIN_GCRYPT_VERSION);
	  return -1;
	}

      /* Disable secure memory warning */
      gcry_control (GCRYCTL_DISABLE_SECMEM_WARN);

      /* Finish initialization */
      gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

      crypto_initialized = 1;
      LWIP_DEBUGF (NETIF_DEBUG, ("wg: crypto initialized with libgcrypt %s\n",
				 gcry_check_version (NULL)));
    }

  return 0;
}

/*
 * Curve25519: Generate keypair
 * Uses Ed25519 keys and converts to Curve25519
 */
int
curve25519_generate_keypair (struct curve25519_keypair *keypair)
{
  gcry_sexp_t sexp_private, sexp_public;
  gcry_mpi_t mpi_private, mpi_public;
  size_t nbits;
  int rc;

  if (!keypair)
    return -EINVAL;

  /* Generate Curve25519 keypair */
  rc = gcry_sexp_build (&sexp_private, NULL, "(genkey (ecc (curve \"Curve25519\")))");
  if (rc)
    {
      error (0, 0, "Curve25519 key generation failed: %s", gcry_strerror (rc));
      return -EIO;
    }

  rc = gcry_pk_genkey (&sexp_public, sexp_private);
  gcry_sexp_release (sexp_private);

  if (rc)
    {
      error (0, 0, "Curve25519 key extraction failed: %s", gcry_strerror (rc));
      return -EIO;
    }

  /* Extract private key */
  mpi_private = gcry_sexp_find_token (sexp_public, "d", 0);
  if (!mpi_private)
    {
      gcry_sexp_release (sexp_public);
      return -EIO;
    }

  nbits = gcry_mpi_get_nbits (mpi_private);
  gcry_mpi_print (GCRYMPI_FMT_USG, keypair->private_key, WG_KEY_LEN,
		  &nbits, mpi_private);
  gcry_mpi_release (mpi_private);

  /* Extract public key */
  mpi_public = gcry_sexp_find_token (sexp_public, "q", 0);
  if (!mpi_public)
    {
      gcry_sexp_release (sexp_public);
      return -EIO;
    }

  nbits = gcry_mpi_get_nbits (mpi_public);
  gcry_mpi_print (GCRYMPI_FMT_USG, keypair->public_key, WG_KEY_LEN,
		  &nbits, mpi_public);
  gcry_mpi_release (mpi_public);
  gcry_sexp_release (sexp_public);

  return 0;
}

/*
 * Curve25519: Derive public key from private key
 */
int
curve25519_public_from_private (uint8_t *public_key, const uint8_t *private_key)
{
  gcry_sexp_t sexp_private, sexp_public;
  gcry_mpi_t mpi_private, mpi_public;
  size_t nbits;
  int rc;

  if (!public_key || !private_key)
    return -EINVAL;

  /* Convert private key to MPI */
  rc = gcry_mpi_scan (&mpi_private, GCRYMPI_FMT_USG, private_key, WG_KEY_LEN, NULL);
  if (rc)
    return -EIO;

  /* Build private key S-expression */
  rc = gcry_sexp_build (&sexp_private, NULL,
			"(private-key (ecc (curve \"Curve25519\") (d %m)))",
			mpi_private);
  if (rc)
    {
      gcry_mpi_release (mpi_private);
      return -EIO;
    }

  /* Extract public key */
  rc = gcry_pk_genkey (&sexp_public, sexp_private);
  gcry_sexp_release (sexp_private);

  if (rc)
    {
      error (0, 0, "Curve25519 public key derivation failed: %s", gcry_strerror (rc));
      return -EIO;
    }

  /* Extract public point */
  mpi_public = gcry_sexp_find_token (sexp_public, "q", 0);
  if (!mpi_public)
    {
      gcry_sexp_release (sexp_public);
      return -EIO;
    }

  nbits = gcry_mpi_get_nbits (mpi_public);
  gcry_mpi_print (GCRYMPI_FMT_USG, public_key, WG_KEY_LEN, &nbits, mpi_public);

  gcry_mpi_release (mpi_public);
  gcry_sexp_release (sexp_public);

  return 0;
}

/*
 * Curve25519: ECDH shared secret derivation
 */
int
curve25519_derive_shared_secret (const uint8_t *private_key,
				 const uint8_t *public_key,
				 uint8_t *shared_secret)
{
  gcry_sexp_t sexp;
  gcry_mpi_t mpi_priv, mpi_pub, mpi_shared;
  size_t nbits;
  int rc;

  if (!private_key || !public_key || !shared_secret)
    return -EINVAL;

  /* Convert keys to MPIs */
  rc = gcry_mpi_scan (&mpi_priv, GCRYMPI_FMT_USG, private_key, WG_KEY_LEN, NULL);
  if (rc)
    return -EIO;

  rc = gcry_mpi_scan (&mpi_pub, GCRYMPI_FMT_USG, public_key, WG_KEY_LEN, NULL);
  if (rc)
    {
      gcry_mpi_release (mpi_priv);
      return -EIO;
    }

  /* Perform ECDH */
  rc = gcry_sexp_build (&sexp, NULL,
			"(ecc (curve \"Curve25519\") (d %m) (q %m))",
			mpi_priv, mpi_pub);
  if (rc)
    {
      gcry_mpi_release (mpi_priv);
      gcry_mpi_release (mpi_pub);
      return -EIO;
    }

  rc = gcry_pk_encrypt (sexp, &sexp);
  gcry_sexp_release (sexp);

  if (rc)
    {
      gcry_mpi_release (mpi_priv);
      gcry_mpi_release (mpi_pub);
      error (0, 0, "ECDH failed: %s", gcry_strerror (rc));
      return -EIO;
    }

  /* Extract shared secret */
  mpi_shared = gcry_sexp_find_token (sexp, "s", 0);
  if (!mpi_shared)
    {
      gcry_sexp_release (sexp);
      gcry_mpi_release (mpi_priv);
      gcry_mpi_release (mpi_pub);
      return -EIO;
    }

  nbits = gcry_mpi_get_nbits (mpi_shared);
  gcry_mpi_print (GCRYMPI_FMT_USG, shared_secret, WG_KEY_LEN, &nbits, mpi_shared);

  gcry_mpi_release (mpi_shared);
  gcry_mpi_release (mpi_priv);
  gcry_mpi_release (mpi_pub);
  gcry_sexp_release (sexp);

  return 0;
}

/*
 * Initialize ChaCha20-Poly1305 context
 */
int
chacha20poly1305_init (struct chacha20poly1305_ctx *ctx,
		       const uint8_t *key, size_t key_len)
{
  int rc;

  if (!ctx || !key || key_len != WG_KEY_LEN)
    return -EINVAL;

  /* Initialize ChaCha20 */
  rc = gcry_cipher_open (&ctx->chacha, GCRY_CIPHER_CHACHA20,
			 GCRY_CIPHER_MODE_STREAM, 0);
  if (rc)
    {
      error (0, 0, "Failed to open ChaCha20: %s", gcry_strerror (rc));
      return -EIO;
    }

  rc = gcry_cipher_setkey (ctx->chacha, key, key_len);
  if (rc)
    {
      gcry_cipher_close (ctx->chacha);
      return -EIO;
    }

  /* Initialize Poly1305 */
  rc = gcry_mac_open (&ctx->poly1305, GCRY_MAC_POLY1305, 0, NULL);
  if (rc)
    {
      gcry_cipher_close (ctx->chacha);
      error (0, 0, "Failed to open Poly1305: %s", gcry_strerror (rc));
      return -EIO;
    }

  /* Set Poly1305 key (first 32 bytes of ChaCha20 output with zero nonce) */
  uint8_t poly_key[32];
  memset (poly_key, 0, 32);
  gcry_cipher_encrypt (ctx->chacha, poly_key, 32, NULL, 0);

  rc = gcry_mac_setkey (ctx->poly1305, poly_key, 32);
  if (rc)
    {
      gcry_cipher_close (ctx->chacha);
      gcry_mac_close (ctx->poly1305);
      return -EIO;
    }

  return 0;
}

/*
 * ChaCha20-Poly1305 AEAD encryption
 */
int
chacha20poly1305_encrypt (struct chacha20poly1305_ctx *ctx,
			  const uint8_t *nonce,
			  const uint8_t *aad, size_t aad_len,
			  const uint8_t *plaintext, size_t plaintext_len,
			  uint8_t *ciphertext, uint8_t *tag)
{
  int rc;

  if (!ctx || !nonce || !plaintext || !ciphertext || !tag)
    return -EINVAL;

  /* Set counter for ChaCha20 (nonce + counter=0) */
  uint8_t full_nonce[16];
  memset (full_nonce, 0, 4);  /* Counter = 0 */
  memcpy (full_nonce + 4, nonce, WG_NONCE_LEN);

  rc = gcry_cipher_setiv (ctx->chacha, full_nonce, sizeof (full_nonce));
  if (rc)
    return -EIO;

  /* Encrypt plaintext */
  rc = gcry_cipher_encrypt (ctx->chacha, ciphertext, plaintext_len,
			    plaintext, plaintext_len);
  if (rc)
    return -EIO;

  /* Calculate Poly1305 tag over AAD and ciphertext */
  rc = gcry_mac_reset (ctx->poly1305);
  if (rc)
    return -EIO;

  /* Pad AAD to 16-byte boundary */
  size_t aad_padded_len = ((aad_len + 15) / 16) * 16;
  uint8_t *aad_padded = NULL;
  if (aad_len > 0)
    {
      aad_padded = malloc (aad_padded_len);
      if (!aad_padded)
	return -ENOMEM;
      memset (aad_padded, 0, aad_padded_len);
      memcpy (aad_padded, aad, aad_len);
      rc = gcry_mac_write (ctx->poly1305, aad_padded, aad_padded_len);
      free (aad_padded);
      if (rc)
	return -EIO;
    }

  /* Pad ciphertext to 16-byte boundary */
  size_t ct_padded_len = ((plaintext_len + 15) / 16) * 16;
  uint8_t *ct_padded = NULL;
  if (plaintext_len > 0)
    {
      ct_padded = malloc (ct_padded_len);
      if (!ct_padded)
	return -ENOMEM;
      memset (ct_padded, 0, ct_padded_len);
      memcpy (ct_padded, ciphertext, plaintext_len);
      rc = gcry_mac_write (ctx->poly1305, ct_padded, ct_padded_len);
      free (ct_padded);
      if (rc)
	return -EIO;
    }

  /* Add lengths */
  uint64_t lengths[2];
  lengths[0] = htole64 (aad_len);
  lengths[1] = htole64 (plaintext_len);
  rc = gcry_mac_write (ctx->poly1305, (uint8_t *)lengths, sizeof (lengths));
  if (rc)
    return -EIO;

  /* Get tag */
  size_t tag_len = WG_TAG_LEN;
  rc = gcry_mac_read (ctx->poly1305, tag, &tag_len);
  if (rc)
    return -EIO;

  return 0;
}

/*
 * ChaCha20-Poly1305 AEAD decryption
 */
int
chacha20poly1305_decrypt (struct chacha20poly1305_ctx *ctx,
			  const uint8_t *nonce,
			  const uint8_t *aad, size_t aad_len,
			  const uint8_t *ciphertext, size_t ciphertext_len,
			  const uint8_t *tag,
			  uint8_t *plaintext)
{
  int rc;

  if (!ctx || !nonce || !ciphertext || !tag || !plaintext)
    return -EINVAL;

  /* Verify tag first */
  uint8_t computed_tag[WG_TAG_LEN];

  /* Reset and recalculate tag */
  rc = gcry_mac_reset (ctx->poly1305);
  if (rc)
    return -EIO;

  /* Pad AAD */
  size_t aad_padded_len = ((aad_len + 15) / 16) * 16;
  uint8_t *aad_padded = NULL;
  if (aad_len > 0)
    {
      aad_padded = malloc (aad_padded_len);
      if (!aad_padded)
	return -ENOMEM;
      memset (aad_padded, 0, aad_padded_len);
      memcpy (aad_padded, aad, aad_len);
      rc = gcry_mac_write (ctx->poly1305, aad_padded, aad_padded_len);
      free (aad_padded);
      if (rc)
	return -EIO;
    }

  /* Pad ciphertext */
  size_t ct_padded_len = ((ciphertext_len + 15) / 16) * 16;
  uint8_t *ct_padded = NULL;
  if (ciphertext_len > 0)
    {
      ct_padded = malloc (ct_padded_len);
      if (!ct_padded)
	return -ENOMEM;
      memset (ct_padded, 0, ct_padded_len);
      memcpy (ct_padded, ciphertext, ciphertext_len);
      rc = gcry_mac_write (ctx->poly1305, ct_padded, ct_padded_len);
      free (ct_padded);
      if (rc)
	return -EIO;
    }

  /* Add lengths */
  uint64_t lengths[2];
  lengths[0] = htole64 (aad_len);
  lengths[1] = htole64 (ciphertext_len);
  rc = gcry_mac_write (ctx->poly1305, (uint8_t *)lengths, sizeof (lengths));
  if (rc)
    return -EIO;

  /* Get and compare tag */
  size_t tag_len = WG_TAG_LEN;
  rc = gcry_mac_read (ctx->poly1305, computed_tag, &tag_len);
  if (rc)
    return -EIO;

  if (memcmp (computed_tag, tag, WG_TAG_LEN) != 0)
    return -EBADMSG;  /* Authentication failed */

  /* Decrypt */
  uint8_t full_nonce[16];
  memset (full_nonce, 0, 4);
  memcpy (full_nonce + 4, nonce, WG_NONCE_LEN);

  rc = gcry_cipher_setiv (ctx->chacha, full_nonce, sizeof (full_nonce));
  if (rc)
    return -EIO;

  rc = gcry_cipher_decrypt (ctx->chacha, plaintext, ciphertext_len,
			    ciphertext, ciphertext_len);
  if (rc)
    return -EIO;

  return 0;
}

/*
 * Close ChaCha20-Poly1305 context
 */
void
chacha20poly1305_close (struct chacha20poly1305_ctx *ctx)
{
  if (!ctx)
    return;

  if (ctx->chacha)
    gcry_cipher_close (ctx->chacha);

  if (ctx->poly1305)
    gcry_mac_close (ctx->poly1305);

  memset (ctx, 0, sizeof (*ctx));
}

/*
 * BLAKE2s hash
 */
int
blake2s_hash (uint8_t *output, size_t outlen,
	      const uint8_t *data, size_t data_len)
{
  gcry_md_hd_t md;
  int rc;

  if (!output || !data || outlen > 32)
    return -EINVAL;

  rc = gcry_md_open (&md, GCRY_MD_BLAKE2S_256, 0);
  if (rc)
    {
      error (0, 0, "Failed to open BLAKE2s: %s", gcry_strerror (rc));
      return -EIO;
    }

  gcry_md_write (md, data, data_len);
  memcpy (output, gcry_md_read (md, GCRY_MD_BLAKE2S_256), outlen);

  gcry_md_close (md);
  return 0;
}

/*
 * BLAKE2s HMAC
 */
int
blake2s_hmac (uint8_t *output, size_t outlen,
	      const uint8_t *key, size_t key_len,
	      const uint8_t *data, size_t data_len)
{
  gcry_md_hd_t md;
  int rc;

  if (!output || !key || !data || outlen > 32)
    return -EINVAL;

  rc = gcry_md_open (&md, GCRY_MD_BLAKE2S_256, GCRY_MD_FLAG_HMAC);
  if (rc)
    {
      error (0, 0, "Failed to open BLAKE2s HMAC: %s", gcry_strerror (rc));
      return -EIO;
    }

  rc = gcry_md_setkey (md, key, key_len);
  if (rc)
    {
      gcry_md_close (md);
      return -EIO;
    }

  gcry_md_write (md, data, data_len);
  memcpy (output, gcry_md_read (md, GCRY_MD_BLAKE2S_256), outlen);

  gcry_md_close (md);
  return 0;
}

/*
 * WireGuard Key Derivation Function using BLAKE2s
 */
void
wg_kdf (uint8_t *t1, uint8_t *t2, uint8_t *t3,
	const uint8_t *secret, size_t secret_len,
	const uint8_t *chain_key, size_t chain_key_len)
{
  uint8_t k[WG_HASH_LEN];
  uint8_t output[WG_HASH_LEN + 1];

  /* t1 = HMAC(chain_key, secret || 0x01) */
  blake2s_hmac (k, WG_HASH_LEN, chain_key, chain_key_len, secret, secret_len);
  output[0] = 0x01;
  memcpy (output + 1, k, WG_HASH_LEN);
  blake2s_hmac (t1 ?: output, WG_HASH_LEN, chain_key, chain_key_len,
		output, WG_HASH_LEN + 1);

  if (!t1)
    t1 = output;

  /* t2 = HMAC(t1, secret || 0x02) */
  if (t2)
    {
      output[0] = 0x02;
      memcpy (output + 1, k, WG_HASH_LEN);
      blake2s_hmac (t2, WG_HASH_LEN, t1, WG_HASH_LEN, output, WG_HASH_LEN + 1);
    }

  /* t3 = HMAC(t2, secret || 0x03) */
  if (t3)
    {
      output[0] = 0x03;
      memcpy (output + 1, k, WG_HASH_LEN);
      blake2s_hmac (t3, WG_HASH_LEN, t2, WG_HASH_LEN, output, WG_HASH_LEN + 1);
    }

  /* Clear sensitive data */
  memset (k, 0, sizeof (k));
  memset (output, 0, sizeof (output));
}

/*
 * SIPHASH-24 for MAC1 (simplified implementation)
 */
int
siphash24 (const uint8_t *key, const uint8_t *data, size_t data_len,
	   uint8_t *output)
{
  /* Use Poly1305 as a substitute for SIPHASH */
  gcry_mac_hd_t mac;
  int rc;
  size_t outlen;

  rc = gcry_mac_open (&mac, GCRY_MAC_POLY1305, 0, NULL);
  if (rc)
    return -EIO;

  rc = gcry_mac_setkey (mac, key, 32);
  if (rc)
    {
      gcry_mac_close (mac);
      return -EIO;
    }

  rc = gcry_mac_write (mac, data, data_len);
  if (rc)
    {
      gcry_mac_close (mac);
      return -EIO;
    }

  outlen = 16;
  rc = gcry_mac_read (mac, output, &outlen);
  gcry_mac_close (mac);

  return rc ? -EIO : 0;
}

/*
 * Cleanup cryptographic resources
 */
void
wg_crypto_cleanup (void)
{
  if (crypto_initialized)
    {
      gcry_control (GCRYCTL_TERM_SECMEM, 0);
      crypto_initialized = 0;
    }
}
