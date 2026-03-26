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

/* WireGuard interface implementation */

#include <netif/hurdwgif.h>
#include "wg-crypto.h"

#include <hurd/trivfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <error.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <lwip-hurd.h>

/* WireGuard protocol constants */
#define WG_HANDSHAKE_INITIATION		1
#define WG_HANDSHAKE_RESPONSE		2
#define WG_HANDSHAKE_COOKIE		3
#define WG_DATA			4

#define WG_KEY_LEN			32
#define WG_MAC1_LEN			16
#define WG_MAC2_LEN			16
#define WG_TAI64N_LEN			12
#define WG_NONCE_LEN			12
#define WG_TAG_LEN			16

/* WireGuard message headers */
struct wg_message_initiation
{
  uint32_t type;
  uint32_t sender;
  uint8_t ephemeral[32];
  uint8_t static_ephemeral[48];
  uint8_t timestamp[28];
  uint8_t mac1[WG_MAC1_LEN];
  uint8_t mac2[WG_MAC2_LEN];
} __attribute__((packed));

struct wg_message_response
{
  uint32_t type;
  uint32_t sender;
  uint32_t receiver;
  uint8_t ephemeral[32];
  uint8_t empty[16];
  uint8_t mac1[WG_MAC1_LEN];
  uint8_t mac2[WG_MAC2_LEN];
} __attribute__((packed));

struct wg_message_data
{
  uint32_t type;
  uint32_t receiver;
  uint64_t counter;
  uint8_t encrypted_data[];
} __attribute__((packed));

struct port_class *wg_cntlclass;
struct port_class *wg_class;

/* Add to the end of the queue */
static void
wg_enqueue (struct wg_pbufqueue *q, struct pbuf *p)
{
  *(q->tail) = p;
  p->next = 0;
  q->tail = &p->next;

  q->len++;
}

/* Get from the head of the queue */
static struct pbuf *
wg_dequeue (struct wg_pbufqueue *q)
{
  struct pbuf *ret;

  if (!q->head)
    return 0;

  ret = q->head;
  q->head = q->head->next;
  ret->next = 0;
  q->len--;

  if (!q->head)
    q->tail = &q->head;

  return ret;
}

/*
 * Simple cryptographic helper functions
 * Using libgcrypt for ChaCha20-Poly1305 and Curve25519
 */
static int
wg_generate_keypair (uint8_t *private_key, uint8_t *public_key)
{
  struct curve25519_keypair keypair;
  int rc;

  rc = curve25519_generate_keypair (&keypair);
  if (rc < 0)
    return rc;

  memcpy (private_key, keypair.private_key, WG_KEY_LEN);
  memcpy (public_key, keypair.public_key, WG_KEY_LEN);

  return 0;
}

static int
wg_derive_shared_secret (uint8_t *private_key, uint8_t *public_key,
			 uint8_t *shared_secret)
{
  return curve25519_derive_shared_secret (private_key, public_key, shared_secret);
}

static int
wg_encrypt_packet (uint8_t *key, uint64_t counter, uint8_t *data, size_t len,
		   uint8_t *output, uint8_t *tag)
{
  struct chacha20poly1305_ctx ctx;
  uint8_t nonce[WG_NONCE_LEN];
  int rc;

  /* Construct nonce: 4 bytes zero + 8 bytes counter (little-endian) */
  memset (nonce, 0, 4);
  for (int i = 0; i < 8; i++)
    nonce[4 + i] = (counter >> (i * 8)) & 0xFF;

  rc = chacha20poly1305_init (&ctx, key, WG_KEY_LEN);
  if (rc < 0)
    return rc;

  rc = chacha20poly1305_encrypt (&ctx, nonce, NULL, 0, data, len, output, tag);
  chacha20poly1305_close (&ctx);

  return rc;
}

static int
wg_decrypt_packet (uint8_t *key, uint64_t counter, uint8_t *data, size_t len,
		   uint8_t *tag, uint8_t *output)
{
  struct chacha20poly1305_ctx ctx;
  uint8_t nonce[WG_NONCE_LEN];
  int rc;

  /* Construct nonce: 4 bytes zero + 8 bytes counter (little-endian) */
  memset (nonce, 0, 4);
  for (int i = 0; i < 8; i++)
    nonce[4 + i] = (counter >> (i * 8)) & 0xFF;

  rc = chacha20poly1305_init (&ctx, key, WG_KEY_LEN);
  if (rc < 0)
    return rc;

  rc = chacha20poly1305_decrypt (&ctx, nonce, NULL, 0, data, len, tag, output);
  chacha20poly1305_close (&ctx);

  return rc;
}

static int
wg_hash (uint8_t *output, size_t outlen, uint8_t *data, size_t datalen)
{
  return blake2s_hash (output, outlen, data, datalen);
}

/*
 * Update the interface's MTU
 */
static error_t
hurdwgif_device_update_mtu (struct netif *netif, uint32_t mtu)
{
  error_t err = 0;

  /* WireGuard overhead: 4 bytes (type+keyidx) + 16 bytes (nonce) +
   * 16 bytes (MAC) + 16 bytes (poly1305) = 52 bytes */
  if (mtu > 1420)
    mtu = 1420;  /* Recommended MTU for WireGuard */

  netif->mtu = mtu;

  return err;
}

/* Set the device flags */
static error_t
hurdwgif_device_set_flags (struct netif *netif, uint16_t flags)
{
  error_t err = 0;
  struct hurdwgif *wgif;

  wgif = netif_get_state (netif);
  wgif->comm.flags = flags;

  return err;
}

/*
 * Release all resources of this netif.
 *
 * Returns 0 on success.
 */
static error_t
hurdwgif_device_terminate (struct netif *netif)
{
  struct pbuf *p;
  struct hurdwgif *wgif = (struct hurdwgif *) netif_get_state (netif);

  /* Clear the queues */
  while ((p = wg_dequeue (&wgif->queue)) != 0)
    pbuf_free (p);
  while ((p = wg_dequeue (&wgif->rx_queue)) != 0)
    pbuf_free (p);

  pthread_cond_destroy (&wgif->read);
  pthread_cond_destroy (&wgif->select);
  pthread_cond_destroy (&wgif->handshake);
  pthread_mutex_destroy (&wgif->lock);

  /* Free the hook */
  free (netif_get_state (netif)->devname);
  free (netif_get_state (netif));

  return 0;
}

/*
 * Process incoming WireGuard packets with ChaCha20-Poly1305 decryption
 */
static void
hurdwgif_process_packet (struct hurdwgif *wgif, struct pbuf *p)
{
  struct wg_message_data *msg;
  struct pbuf *decrypted_p;
  uint8_t *data;
  uint8_t *encrypted_data;
  uint8_t *tag;
  uint8_t *decrypted_payload;
  size_t payload_len;
  uint64_t counter;
  int rc;

  if (p->tot_len < sizeof (uint32_t))
    return;

  /* Get message type */
  data = (uint8_t *) p->payload;
  uint32_t type = ntohl (*(uint32_t *) data);

  switch (type & 0xFF)
    {
    case WG_HANDSHAKE_INITIATION:
      /* Handle handshake initiation */
      LWIP_DEBUGF (NETIF_DEBUG, ("wg: received handshake initiation\n"));
      /* Process handshake and send response */
      break;

    case WG_HANDSHAKE_RESPONSE:
      /* Handle handshake response */
      LWIP_DEBUGF (NETIF_DEBUG, ("wg: received handshake response\n"));
      wgif->handshake_complete = 1;
      pthread_cond_broadcast (&wgif->handshake);
      break;

    case WG_HANDSHAKE_COOKIE:
      /* Handle cookie response */
      LWIP_DEBUGF (NETIF_DEBUG, ("wg: received cookie\n"));
      break;

    case WG_DATA:
      /* Handle data packet */
      msg = (struct wg_message_data *) data;
      LWIP_DEBUGF (NETIF_DEBUG, ("wg: received data packet\n"));

      /* Extract counter and tag */
      counter = be64toh (msg->counter);
      payload_len = p->tot_len - sizeof (struct wg_message_data) - WG_TAG_LEN;
      
      /* Get pointers to encrypted data and tag */
      encrypted_data = msg->encrypted_data;
      tag = encrypted_data + payload_len;

      /* Check replay: counter must be greater than last received */
      pthread_mutex_lock (&wgif->lock);
      if (counter <= wgif->crypto.receiving_counter)
	{
	  LWIP_DEBUGF (NETIF_DEBUG, ("wg: replay attack detected\n"));
	  pthread_mutex_unlock (&wgif->lock);
	  pbuf_free (p);
	  return;
	}
      pthread_mutex_unlock (&wgif->lock);

      /* Allocate buffer for decrypted packet */
      decrypted_p = pbuf_alloc (PBUF_IP, payload_len, PBUF_RAM);
      if (decrypted_p)
	{
	  decrypted_payload = (uint8_t *) decrypted_p->payload;

	  /* Decrypt the packet */
	  rc = wg_decrypt_packet (wgif->crypto.receiving_key,
				  counter,
				  encrypted_data, payload_len,
				  tag,
				  decrypted_payload);

	  if (rc < 0)
	    {
	      LWIP_DEBUGF (NETIF_DEBUG, ("wg: decryption failed\n"));
	      pbuf_free (decrypted_p);
	      pbuf_free (p);
	      return;
	    }

	  /* Update counter and statistics */
	  pthread_mutex_lock (&wgif->lock);
	  wgif->crypto.receiving_counter = counter;
	  wgif->rx_bytes += payload_len;
	  wgif->rx_packets++;
	  pthread_mutex_unlock (&wgif->lock);

	  /* Enqueue decrypted packet */
	  wg_enqueue (&wgif->rx_queue, decrypted_p);

	  /* Wake up readers */
	  if (wgif->read_blocked)
	    {
	      wgif->read_blocked = 0;
	      pthread_cond_broadcast (&wgif->read);
	      pthread_cond_broadcast (&wgif->select);
	    }
	}
      break;

    default:
      LWIP_DEBUGF (NETIF_DEBUG, ("wg: unknown message type %d\n", type));
      break;
    }

  pbuf_free (p);
}

/*
 * Called from lwip.
 *
 * Encrypt and enqueue the data using ChaCha20-Poly1305.
 */
static err_t
hurdwgif_output (struct netif *netif, struct pbuf *p,
		 const ip4_addr_t * ipaddr)
{
  struct hurdwgif *wgif;
  struct pbuf *encrypted_p;
  uint8_t *data;
  size_t encrypted_len;
  uint8_t tag[WG_TAG_LEN];
  err_t err;

  wgif = (struct hurdwgif *) netif_get_state (netif);

  if (!wgif->configured)
    {
      LWIP_DEBUGF (NETIF_DEBUG, ("wg: interface not configured\n"));
      return ERR_IF;
    }

  /* Wait for handshake if needed */
  pthread_mutex_lock (&wgif->lock);
  while (!wgif->handshake_complete)
    {
      /* Send handshake initiation */
      LWIP_DEBUGF (NETIF_DEBUG, ("wg: initiating handshake\n"));
      /* In production: send handshake packet */
      wgif->handshake_blocked = 1;
      if (pthread_hurd_cond_timedwait_np (&wgif->handshake, &wgif->lock, NULL))
	{
	  pthread_mutex_unlock (&wgif->lock);
	  return ERR_TIMEOUT;
	}
    }
  pthread_mutex_unlock (&wgif->lock);

  /* Allocate encrypted packet: original + WireGuard header + Poly1305 tag */
  encrypted_len = p->tot_len + sizeof (struct wg_message_data) + WG_TAG_LEN;
  encrypted_p = pbuf_alloc (PBUF_RAW, encrypted_len, PBUF_RAM);
  if (encrypted_p != NULL)
    {
      /* Build WireGuard packet header */
      struct wg_message_data *wg_msg = (struct wg_message_data *) encrypted_p->payload;
      wg_msg->type = htonl (WG_DATA);
      wg_msg->receiver = 0;  /* Key index */
      wg_msg->counter = htobe64 (wgif->crypto.sending_counter);

      /* Copy and encrypt payload */
      data = (uint8_t *) p->payload;
      err = wg_encrypt_packet (wgif->crypto.sending_key,
			       wgif->crypto.sending_counter,
			       data, p->tot_len,
			       wg_msg->encrypted_data, tag);

      if (err < 0)
	{
	  pbuf_free (encrypted_p);
	  return ERR_IF;
	}

      /* Copy tag to end of encrypted data */
      memcpy (wg_msg->encrypted_data + p->tot_len, tag, WG_TAG_LEN);

      /* Update statistics and counter */
      wgif->tx_bytes += p->tot_len;
      wgif->tx_packets++;
      wgif->crypto.sending_counter++;

      pthread_mutex_lock (&wgif->lock);
      wg_enqueue (&wgif->queue, encrypted_p);

      if (wgif->read_blocked)
	{
	  wgif->read_blocked = 0;
	  pthread_cond_broadcast (&wgif->read);
	  pthread_cond_broadcast (&wgif->select);
	}
      pthread_mutex_unlock (&wgif->lock);
    }

  return ERR_OK;
}

/*
 * Set up a new WireGuard interface
 */
err_t
hurdwgif_device_init (struct netif *netif)
{
  error_t err = 0;
  struct hurdwgif *wgif;
  char *base_name, *name = netif_get_state (netif)->devname;

  /* Initialize crypto library on first use */
  if (wg_crypto_init () < 0)
    {
      LWIP_DEBUGF (NETIF_DEBUG, ("hurdwgif_init: crypto initialization failed\n"));
      return ERR_IF;
    }

  /*
   * Replace the hook by a new one with the proper size.
   * The old one is in the stack and will be removed soon.
   */
  wgif = calloc (1, sizeof (struct hurdwgif));
  if (wgif == NULL)
    {
      LWIP_DEBUGF (NETIF_DEBUG, ("hurdwgif_init: out of memory\n"));
      return ERR_MEM;
    }
  memcpy (wgif, netif_get_state (netif), sizeof (struct ifcommon));
  netif->state = wgif;

  base_name = strrchr (name, '/');
  if (base_name)
    base_name++;
  else
    base_name = name;

  if (base_name != name)
    wgif->comm.devname = strdup (name);
  else
    asprintf (&wgif->comm.devname, "/dev/%s", base_name);

  /* Set the device type */
  wgif->comm.type = ARPHRD_NONE;

  /* Default MTU for WireGuard */
  netif->mtu = 1420;

  /* Set flags */
  hurdwgif_device_set_flags (netif,
			     IFF_UP | IFF_POINTOPOINT | IFF_NOARP);

  netif->flags = NETIF_FLAG_LINK_UP;

  /* Set the callbacks */
  netif->output = hurdwgif_output;
  wgif->comm.open = 0;
  wgif->comm.close = 0;
  wgif->comm.terminate = hurdwgif_device_terminate;
  wgif->comm.update_mtu = hurdwgif_device_update_mtu;
  wgif->comm.change_flags = hurdwgif_device_set_flags;

  /* Initialize configuration */
  memset (&wgif->config, 0, sizeof (struct wg_config));
  memset (&wgif->crypto, 0, sizeof (struct wg_crypto_state));
  wgif->configured = 0;
  wgif->handshake_complete = 0;

  /* Initialize queues */
  wgif->queue.head = 0;
  wgif->queue.tail = &wgif->queue.head;
  wgif->queue.len = 0;

  wgif->rx_queue.head = 0;
  wgif->rx_queue.tail = &wgif->rx_queue.head;
  wgif->rx_queue.len = 0;

  /* Initialize synchronization primitives */
  pthread_mutex_init (&wgif->lock, NULL);
  pthread_cond_init (&wgif->read, NULL);
  pthread_cond_init (&wgif->select, NULL);
  pthread_cond_init (&wgif->handshake, NULL);
  wgif->read_blocked = 0;
  wgif->handshake_blocked = 0;

  /* Initialize statistics */
  wgif->tx_bytes = 0;
  wgif->rx_bytes = 0;
  wgif->tx_packets = 0;
  wgif->rx_packets = 0;

  return ERR_OK;
}

/*
 * Set libports classes
 *
 * This function should be called once.
 */
error_t
hurdwgif_module_init (void)
{
  error_t err = 0;

  trivfs_add_control_port_class (&wg_cntlclass);
  trivfs_add_protid_port_class (&wg_class);

  return err;
}

/* Configure WireGuard interface */
error_t
hurdwgif_configure (struct hurdwgif *wgif, struct wg_config *cfg)
{
  if (!wgif || !cfg)
    return EINVAL;

  pthread_mutex_lock (&wgif->lock);
  memcpy (&wgif->config, cfg, sizeof (struct wg_config));
  wgif->configured = 1;
  pthread_mutex_unlock (&wgif->lock);

  LWIP_DEBUGF (NETIF_DEBUG, ("wg: interface configured\n"));
  return 0;
}

/* Get WireGuard configuration */
error_t
hurdwgif_get_config (struct hurdwgif *wgif, struct wg_config *cfg)
{
  if (!wgif || !cfg)
    return EINVAL;

  pthread_mutex_lock (&wgif->lock);
  memcpy (cfg, &wgif->config, sizeof (struct wg_config));
  pthread_mutex_unlock (&wgif->lock);

  return 0;
}

/* Set private key */
error_t
hurdwgif_set_private_key (struct hurdwgif *wgif, uint8_t *key)
{
  if (!wgif || !key)
    return EINVAL;

  pthread_mutex_lock (&wgif->lock);
  memcpy (wgif->config.private_key, key, WG_KEY_LEN);
  
  /* Derive public key from private key using Curve25519 */
  if (curve25519_public_from_private (wgif->config.public_key, key) < 0)
    {
      pthread_mutex_unlock (&wgif->lock);
      return EIO;
    }
  
  /* Initialize chain key for KDF */
  wg_hash (wgif->crypto.chain_key, WG_KEY_LEN,
	   wgif->config.public_key, WG_KEY_LEN);
  
  pthread_mutex_unlock (&wgif->lock);

  return 0;
}

/* Set peer public key */
error_t
hurdwgif_set_peer_public_key (struct hurdwgif *wgif, uint8_t *key)
{
  if (!wgif || !key)
    return EINVAL;

  pthread_mutex_lock (&wgif->lock);
  memcpy (wgif->config.peer_public_key, key, WG_KEY_LEN);
  
  /* Perform ECDH to derive shared secret */
  uint8_t shared_secret[WG_KEY_LEN];
  if (wg_derive_shared_secret (wgif->config.private_key, key, shared_secret) < 0)
    {
      pthread_mutex_unlock (&wgif->lock);
      return EIO;
    }
  
  /* Derive sending and receiving keys using KDF */
  wg_kdf (wgif->crypto.sending_key, wgif->crypto.receiving_key, NULL,
	  shared_secret, WG_KEY_LEN,
	  wgif->crypto.chain_key, WG_KEY_LEN);
  
  memset (shared_secret, 0, WG_KEY_LEN);
  pthread_mutex_unlock (&wgif->lock);

  return 0;
}

/* Set preshared key */
error_t
hurdwgif_set_preshared_key (struct hurdwgif *wgif, uint8_t *key)
{
  if (!wgif || !key)
    return EINVAL;

  pthread_mutex_lock (&wgif->lock);
  memcpy (wgif->config.preshared_key, key, WG_KEY_LEN);
  pthread_mutex_unlock (&wgif->lock);

  return 0;
}

/* Add peer */
error_t
hurdwgif_add_peer (struct hurdwgif *wgif, struct in_addr *endpoint,
		   uint16_t port, uint8_t *public_key)
{
  if (!wgif || !endpoint || !public_key)
    return EINVAL;

  pthread_mutex_lock (&wgif->lock);
  wgif->config.peer_endpoint = *endpoint;
  wgif->config.peer_port = port;
  memcpy (wgif->config.peer_public_key, public_key, WG_KEY_LEN);
  pthread_mutex_unlock (&wgif->lock);

  return 0;
}

/* If a new open with read and/or write permissions is requested,
   restrict to exclusive usage.  */
static error_t
wg_check_open_hook (struct trivfs_control *cntl, struct iouser *user, int flags)
{
  struct netif *netif;
  struct hurdwgif *wgif;

  NETIF_FOREACH(netif)
    {
      wgif = (struct hurdwgif *) netif_get_state (netif);
      if (wgif && wgif->cntl == cntl)
	break;
    }

  if (netif && flags != O_NORW)
    {
      if (wgif->user)
	return EBUSY;
      else
	wgif->user = user;
    }

  return 0;
}

/* When a protid is destroyed, check if it is the current user.
   If yes, release the interface for other users.  */
static void
wg_pi_destroy_hook (struct trivfs_protid *cred)
{
  struct netif *netif;
  struct hurdwgif *wgif;

  if (cred->pi.class != wg_class)
    return;

  netif = (struct netif *) cred->po->cntl->hook;
  wgif = (struct hurdwgif *) netif_get_state (netif);

  if (wgif->user == cred->user)
    wgif->user = 0;
}

/* If this variable is set, it is called every time a new peropen
   structure is created and initialized. */
error_t (*trivfs_check_open_hook) (struct trivfs_control *,
				   struct iouser *, int) = wg_check_open_hook;

/* If this variable is set, it is called every time a protid structure
   is about to be destroyed. */
void (*trivfs_protid_destroy_hook) (struct trivfs_protid *) = wg_pi_destroy_hook;

/* Read data from an IO object */
error_t
trivfs_S_io_read (struct trivfs_protid *cred,
		  mach_port_t reply, mach_msg_type_name_t reply_type,
		  data_t *data, mach_msg_type_number_t * data_len,
		  loff_t offs, vm_size_t amount)
{
  struct hurdwgif *wgif;
  struct pbuf *p;

  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  wgif =
    (struct hurdwgif *)
    netif_get_state (((struct netif *) cred->po->cntl->hook));

  pthread_mutex_lock (&wgif->lock);

  while (wgif->rx_queue.len == 0)
    {
      if (cred->po->openmodes & O_NONBLOCK)
	{
	  pthread_mutex_unlock (&wgif->lock);
	  return EWOULDBLOCK;
	}

      wgif->read_blocked = 1;
      if (pthread_hurd_cond_wait_np (&wgif->read, &wgif->lock))
	{
	  pthread_mutex_unlock (&wgif->lock);
	  return EINTR;
	}
    }

  p = wg_dequeue (&wgif->rx_queue);

  if (p->tot_len < amount)
    amount = p->tot_len;
  if (amount > 0)
    {
      if (*data_len < amount)
	{
	  *data = mmap (0, amount, PROT_READ | PROT_WRITE, MAP_ANON, 0, 0);
	  if (*data == MAP_FAILED)
	    {
	      pbuf_free (p);
	      pthread_mutex_unlock (&wgif->lock);
	      return ENOMEM;
	    }
	}

      memcpy ((char *) *data, p->payload, amount);
    }
  *data_len = amount;
  pbuf_free (p);

  pthread_mutex_unlock (&wgif->lock);

  return 0;
}

/* Write data to an IO object */
error_t
trivfs_S_io_write (struct trivfs_protid * cred,
		   mach_port_t reply,
		   mach_msg_type_name_t replytype,
		   const_data_t data,
		   mach_msg_type_number_t datalen,
		   off_t offset, vm_size_t * amount)
{
  struct netif *netif;
  struct pbuf *p, *q;
  uint16_t off;

  if (!cred)
    return EOPNOTSUPP;

  else if (!(cred->po->openmodes & O_WRITE))
    return EBADF;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  netif = (struct netif *) cred->po->cntl->hook;

  /* Process incoming WireGuard packet */
  p = pbuf_alloc (PBUF_RAW, datalen, PBUF_POOL);

  if (p)
    {
      q = p;
      off = 0;
      do
	{
	  memcpy (q->payload, data, q->len);

	  off += q->len;

	  if (q->tot_len == q->len)
	    break;
	  else
	    q = q->next;
	}
      while (1);

      /* Process the WireGuard packet */
      hurdwgif_process_packet (netif_get_state (netif), p);

      *amount = datalen;
    }

  return 0;
}

/* Tell how much data can be read */
kern_return_t
trivfs_S_io_readable (struct trivfs_protid * cred,
		      mach_port_t reply, mach_msg_type_name_t replytype,
		      vm_size_t * amount)
{
  struct hurdwgif *wgif;

  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  wgif =
    (struct hurdwgif *)
    netif_get_state (((struct netif *) cred->po->cntl->hook));

  pthread_mutex_lock (&wgif->lock);

  if (wgif->rx_queue.head)
    *amount = wgif->rx_queue.head->tot_len;
  else
    *amount = 0;

  pthread_mutex_unlock (&wgif->lock);

  return 0;
}

/* Select implementation */
static error_t
wg_io_select_common (struct trivfs_protid *cred,
		     mach_port_t reply,
		     mach_msg_type_name_t reply_type,
		     struct timespec *tsp, int *type)
{
  error_t err;
  struct hurdwgif *wgif;

  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  ports_interrupt_self_on_port_death (cred, reply);

  *type &= SELECT_READ | SELECT_WRITE;

  if (*type == 0)
    return 0;

  wgif =
    (struct hurdwgif *)
    netif_get_state (((struct netif *) cred->po->cntl->hook));

  pthread_mutex_lock (&wgif->lock);

  if (*type & SELECT_WRITE)
    {
      if (wgif->rx_queue.len == 0)
	*type &= ~SELECT_READ;
      pthread_mutex_unlock (&wgif->lock);
      return 0;
    }

  while (1)
    {
      if (wgif->rx_queue.len != 0)
	{
	  *type = SELECT_READ;
	  pthread_mutex_unlock (&wgif->lock);
	  return 0;
	}

      wgif->read_blocked = 1;
      err =
	pthread_hurd_cond_timedwait_np (&wgif->select, &wgif->lock, tsp);
      if (err)
	{
	  *type = 0;
	  pthread_mutex_unlock (&wgif->lock);

	  if (err == ETIMEDOUT)
	    err = 0;

	  return err;
	}
    }
}

error_t
trivfs_S_io_select (struct trivfs_protid * cred,
		    mach_port_t reply,
		    mach_msg_type_name_t reply_type, int *type)
{
  return wg_io_select_common (cred, reply, reply_type, NULL, type);
}

error_t
trivfs_S_io_select_timeout (struct trivfs_protid * cred,
			    mach_port_t reply,
			    mach_msg_type_name_t reply_type,
			    struct timespec ts, int *type)
{
  return wg_io_select_common (cred, reply, reply_type, &ts, type);
}

/* Ioctl for WireGuard configuration */
error_t
trivfs_S_iioctl (struct trivfs_protid *cred,
		 mach_port_t reply,
		 mach_msg_type_name_t reply_type,
		 int request, void *data,
		 mach_msg_type_number_t data_len)
{
  struct hurdwgif *wgif;

  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  wgif =
    (struct hurdwgif *)
    netif_get_state (((struct netif *) cred->po->cntl->hook));

  /* WireGuard-specific ioctls would go here */
  /* For now, return unsupported */
  return ENOTTY;
}

/* Additional trivfs stubs */
error_t
trivfs_S_io_seek (struct trivfs_protid * cred,
		  mach_port_t reply, mach_msg_type_name_t reply_type,
		  off_t offs, int whence, off_t * new_offs)
{
  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  return ESPIPE;
}

error_t
trivfs_S_file_set_size (struct trivfs_protid * cred,
			mach_port_t reply, mach_msg_type_name_t reply_type,
			off_t size)
{
  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  return size == 0 ? 0 : EINVAL;
}

error_t
trivfs_S_io_set_all_openmodes (struct trivfs_protid * cred,
			       mach_port_t reply,
			       mach_msg_type_name_t reply_type, int mode)
{
  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  return 0;
}

error_t
trivfs_S_io_set_some_openmodes (struct trivfs_protid * cred,
				mach_port_t reply,
				mach_msg_type_name_t reply_type, int bits)
{
  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  return 0;
}

error_t
trivfs_S_io_clear_some_openmodes (struct trivfs_protid * cred,
				  mach_port_t reply,
				  mach_msg_type_name_t reply_type, int bits)
{
  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  return 0;
}

error_t
trivfs_S_io_get_owner (struct trivfs_protid * cred,
		       mach_port_t reply,
		       mach_msg_type_name_t reply_type, pid_t * owner)
{
  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  *owner = 0;
  return 0;
}

error_t
trivfs_S_io_mod_owner (struct trivfs_protid * cred,
		       mach_port_t reply, mach_msg_type_name_t reply_type,
		       pid_t owner)
{
  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  return EINVAL;
}

error_t
trivfs_S_io_map (struct trivfs_protid * cred,
		 mach_port_t reply,
		 mach_msg_type_name_t replyPoly,
		 memory_object_t * rdobj,
		 mach_msg_type_name_t * rdtype,
		 memory_object_t * wrobj, mach_msg_type_name_t * wrtype)
{
  if (!cred)
    return EOPNOTSUPP;

  if (cred->pi.class != wg_class)
    return EOPNOTSUPP;

  return EINVAL;
}
