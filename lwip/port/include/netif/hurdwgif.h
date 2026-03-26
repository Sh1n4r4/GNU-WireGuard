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

/* WireGuard interface module */

#ifndef LWIP_HURDWGIF_H
#define LWIP_HURDWGIF_H

#include <hurd/ports.h>

#include <lwip/netif.h>
#include <netif/ifcommon.h>

/* WireGuard cryptographic context */
struct wg_crypto_state
{
  uint8_t sending_key[WG_KEY_LEN];
  uint8_t receiving_key[WG_KEY_LEN];
  uint64_t sending_counter;
  uint64_t receiving_counter;
  uint8_t chain_key[WG_KEY_LEN];
  uint8_t handshake_hash[WG_KEY_LEN];
};

/* WireGuard configuration structure */
struct wg_config
{
  uint16_t listen_port;
  uint8_t private_key[WG_KEY_LEN];	/* 256-bit private key */
  uint8_t public_key[WG_KEY_LEN];	/* 256-bit public key */
  uint8_t peer_public_key[WG_KEY_LEN];	/* 256-bit peer public key */
  uint8_t preshared_key[WG_KEY_LEN];	/* 256-bit preshared key (optional) */
  struct in_addr peer_endpoint;		/* Peer IP address */
  uint16_t peer_port;			/* Peer port */
  uint32_t allowed_ips[4];		/* Allowed IP ranges */
  uint8_t allowed_cidr[4];		/* CIDR prefixes for allowed IPs */
  uint8_t has_preshared_key;		/* Preshared key flag */
};

/* Queue of data for WireGuard interface */
struct wg_pbufqueue
{
  struct pbuf *head;
  struct pbuf **tail;
  uint8_t len;
};

/* WireGuard interface private data */
struct hurdwgif
{
  struct ifcommon comm;

  struct trivfs_control *cntl;	/* Control port for the interface */
  file_t underlying;		/* Underlying node */
  struct iouser *user;		/* Exclusive access user */
  struct wg_pbufqueue queue;	/* Output queue */
  struct wg_pbufqueue rx_queue;	/* Input queue for decrypted packets */

  /* WireGuard configuration */
  struct wg_config config;
  struct wg_crypto_state crypto;	/* Cryptographic state */
  uint8_t configured;		/* Interface is configured */
  uint8_t handshake_complete;	/* Handshake completed */

  /* Concurrent access */
  pthread_mutex_t lock;
  pthread_cond_t read;
  pthread_cond_t select;
  pthread_cond_t handshake;
  uint8_t read_blocked;
  uint8_t handshake_blocked;

  /* Statistics */
  uint64_t tx_bytes;
  uint64_t rx_bytes;
  uint64_t tx_packets;
  uint64_t rx_packets;
};

extern struct port_class *wg_cntlclass;
extern struct port_class *wg_class;

/* Device initialization */
err_t hurdwgif_device_init (struct netif *netif);

/* Module initialization */
error_t hurdwgif_module_init (void);

/* WireGuard configuration ioctls */
error_t hurdwgif_configure (struct hurdwgif *wgif, struct wg_config *cfg);
error_t hurdwgif_get_config (struct hurdwgif *wgif, struct wg_config *cfg);
error_t hurdwgif_set_private_key (struct hurdwgif *wgif, uint8_t *key);
error_t hurdwgif_set_peer_public_key (struct hurdwgif *wgif, uint8_t *key);
error_t hurdwgif_set_preshared_key (struct hurdwgif *wgif, uint8_t *key);
error_t hurdwgif_add_peer (struct hurdwgif *wgif, struct in_addr *endpoint,
			   uint16_t port, uint8_t *public_key);

#endif /* LWIP_HURDWGIF_H */
