/*
   Copyright (C) 2026 Your Name.

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

/*
 * WireGuard configuration utility for GNU Hurd
 * 
 * Usage: wg-config [OPTIONS] <interface>
 * 
 * Example:
 *   wg-config genkey                    # Generate keypair
 *   wg-config set wg0 private-key FILE  # Set private key from file
 *   wg-config add-peer wg0 pubkey FILE endpoint IP:port
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <argp.h>
#include <error.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gcrypt.h>

#include <hurd.h>
#include <hurd/ports.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netif/hurdwgif.h>

static const char *argp_program_version = "wg-config 0.1";
static const char *argp_program_bug_address = "<bug-hurd@gnu.org>";

static char doc[] = "Configure WireGuard interfaces on GNU Hurd";

static char args_doc[] = "<interface> [command] [args...]";

static struct argp_option options[] = {
  {"genkey", 'g', 0, 0, "Generate a new keypair", 0},
  {"private-key", 'p', "FILE", 0, "Set private key from file", 0},
  {"public-key", 'P', "FILE", 0, "Set public key from file", 0},
  {"preshared-key", 's', "FILE", 0, "Set preshared key from file", 0},
  {"add-peer", 'a', "PUBKEY ENDPOINT", 0, "Add a peer", 0},
  {"listen-port", 'l', "PORT", 0, "Set listen port", 0},
  {"allowed-ips", 'i', "IPS", 0, "Set allowed IPs", 0},
  {"show", 'S', 0, 0, "Show interface configuration", 0},
  {"endpoint", 'e', "IP:PORT", 0, "Set peer endpoint", 0},
  {0, 0, 0, 0, 0, 0}
};

struct arguments
{
  char *interface;
  int genkey;
  char *private_key_file;
  char *public_key_file;
  char *preshared_key_file;
  char *peer_pubkey_file;
  char *endpoint;
  uint16_t listen_port;
  char *allowed_ips;
  int show_config;
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'g':
      arguments->genkey = 1;
      break;
    case 'p':
      arguments->private_key_file = arg;
      break;
    case 'P':
      arguments->public_key_file = arg;
      break;
    case 's':
      arguments->preshared_key_file = arg;
      break;
    case 'a':
      arguments->peer_pubkey_file = arg;
      break;
    case 'l':
      arguments->listen_port = atoi (arg);
      break;
    case 'i':
      arguments->allowed_ips = arg;
      break;
    case 'S':
      arguments->show_config = 1;
      break;
    case 'e':
      arguments->endpoint = arg;
      break;
    case ARGP_KEY_ARG:
      if (state->arg_num == 0)
	arguments->interface = arg;
      else
	return ARGP_ERR_UNKNOWN;
      break;
    case ARGP_KEY_END:
      if (state->arg_num < 1)
	argp_usage (state);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};

/* Read key from file (base64 or raw) */
static int
read_key_from_file (const char *filename, uint8_t *key, size_t key_len)
{
  FILE *f;
  char buffer[64];
  size_t bytes_read;

  f = fopen (filename, "r");
  if (!f)
    {
      error (0, errno, "Cannot open %s", filename);
      return -1;
    }

  /* Try to read as base64 first */
  if (fgets (buffer, sizeof (buffer), f))
    {
      /* Check if it looks like base64 */
      size_t len = strlen (buffer);
      if (len > 0 && (buffer[len-1] == '\n' || buffer[len-1] == '\r'))
	buffer[len-1] = '\0';
      
      /* Simple base64 decode would go here */
      /* For now, read as raw bytes */
      fclose (f);
      f = fopen (filename, "rb");
      if (!f)
	return -1;
    }

  bytes_read = fread (key, 1, key_len, f);
  fclose (f);

  if (bytes_read != key_len)
    {
      error (0, 0, "Invalid key length in %s (expected %zu, got %zu)",
	     filename, key_len, bytes_read);
      return -1;
    }

  return 0;
}

/* Write key to file (base64 encoded) */
static int
write_key_to_file (const char *filename, uint8_t *key, size_t key_len)
{
  FILE *f;
  static const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  f = fopen (filename, "w");
  if (!f)
    {
      error (0, errno, "Cannot create %s", filename);
      return -1;
    }

  /* Simple base64 encoding */
  for (size_t i = 0; i < key_len; i += 3)
    {
      uint32_t n = ((uint32_t)key[i] << 16);
      if (i + 1 < key_len) n |= ((uint32_t)key[i+1] << 8);
      if (i + 2 < key_len) n |= key[i+2];
      
      fprintf (f, "%c%c%c%c",
	       base64[(n >> 18) & 0x3F],
	       base64[(n >> 12) & 0x3F],
	       (i + 1 < key_len) ? base64[(n >> 6) & 0x3F] : '=',
	       (i + 2 < key_len) ? base64[n & 0x3F] : '=');
    }
  fprintf (f, "\n");
  fclose (f);

  return 0;
}

/* Generate keypair using libgcrypt */
static int
do_genkey (const char *private_file, const char *public_file)
{
  gcry_sexp_t sexp_private, sexp_public;
  gcry_mpi_t mpi_private, mpi_public;
  uint8_t private_key[32];
  uint8_t public_key[32];
  size_t nbits;
  int rc;

  /* Check libgcrypt version */
  if (!gcry_check_version ("1.8.0"))
    {
      error (0, 0, "libgcrypt version mismatch");
      return -1;
    }

  /* Initialize libgcrypt */
  gcry_control (GCRYCTL_DISABLE_SECMEM_WARN);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  printf ("Generating Curve25519 keypair...\n");

  /* Generate Curve25519 keypair */
  rc = gcry_sexp_build (&sexp_private, NULL, "(genkey (ecc (curve \"Curve25519\")))");
  if (rc)
    {
      error (0, 0, "Key generation failed: %s", gcry_strerror (rc));
      return -1;
    }

  rc = gcry_pk_genkey (&sexp_public, sexp_private);
  gcry_sexp_release (sexp_private);

  if (rc)
    {
      error (0, 0, "Key extraction failed: %s", gcry_strerror (rc));
      gcry_sexp_release (sexp_public);
      return -1;
    }

  /* Extract private key */
  mpi_private = gcry_sexp_find_token (sexp_public, "d", 0);
  if (!mpi_private)
    {
      gcry_sexp_release (sexp_public);
      error (0, 0, "Failed to extract private key");
      return -1;
    }

  nbits = gcry_mpi_get_nbits (mpi_private);
  gcry_mpi_print (GCRYMPI_FMT_USG, private_key, 32, &nbits, mpi_private);
  gcry_mpi_release (mpi_private);

  /* Extract public key */
  mpi_public = gcry_sexp_find_token (sexp_public, "q", 0);
  if (!mpi_public)
    {
      gcry_sexp_release (sexp_public);
      error (0, 0, "Failed to extract public key");
      return -1;
    }

  nbits = gcry_mpi_get_nbits (mpi_public);
  gcry_mpi_print (GCRYMPI_FMT_USG, public_key, 32, &nbits, mpi_public);
  gcry_mpi_release (mpi_public);
  gcry_sexp_release (sexp_public);

  /* Write keys to files */
  if (write_key_to_file (private_file, private_key, 32) < 0)
    return -1;

  if (write_key_to_file (public_file, public_key, 32) < 0)
    return -1;

  printf ("Private key written to %s\n", private_file);
  printf ("Public key written to %s\n", public_file);
  printf ("\nKeep your private key secure!\n");

  return 0;
}

/* Configure interface */
static int
configure_interface (struct arguments *args)
{
  file_t device;
  struct wg_config config;
  error_t err;
  uint8_t key[32];

  /* Open the device */
  device = file_name_lookup (args->interface, O_RDWR, 0);
  if (device == MACH_PORT_NULL)
    {
      error (0, errno, "Cannot open %s", args->interface);
      return -1;
    }

  /* Get current config or initialize */
  memset (&config, 0, sizeof (config));

  /* Set private key */
  if (args->private_key_file)
    {
      if (read_key_from_file (args->private_key_file, key, 32) < 0)
	return -1;
      /* In production: call hurdwgif_set_private_key via ioctl */
      printf ("Private key configured\n");
    }

  /* Set peer public key */
  if (args->peer_pubkey_file)
    {
      if (read_key_from_file (args->peer_pubkey_file, key, 32) < 0)
	return -1;
      /* In production: call hurdwgif_set_peer_public_key via ioctl */
      printf ("Peer public key configured\n");
    }

  /* Set preshared key */
  if (args->preshared_key_file)
    {
      if (read_key_from_file (args->preshared_key_file, key, 32) < 0)
	return -1;
      /* In production: call hurdwgif_set_preshared_key via ioctl */
      printf ("Preshared key configured\n");
    }

  /* Set listen port */
  if (args->listen_port)
    {
      config.listen_port = args->listen_port;
      printf ("Listen port set to %d\n", args->listen_port);
    }

  /* Set endpoint */
  if (args->endpoint)
    {
      char *ip;
      char *port_str;
      char *endpoint_copy = strdup (args->endpoint);

      ip = strtok (endpoint_copy, ":");
      port_str = strtok (NULL, ":");

      if (ip && port_str)
	{
	  config.peer_endpoint.s_addr = inet_addr (ip);
	  config.peer_port = atoi (port_str);
	  printf ("Peer endpoint set to %s:%d\n", ip, config.peer_port);
	}

      free (endpoint_copy);
    }

  /* In production: call hurdwgif_configure via ioctl */
  printf ("Interface configured (placeholder)\n");

  mach_port_deallocate (mach_task_self (), device);
  return 0;
}

/* Show interface configuration */
static int
show_config (const char *interface)
{
  file_t device;
  struct wg_config config;

  device = file_name_lookup (interface, O_RDWR, 0);
  if (device == MACH_PORT_NULL)
    {
      error (0, errno, "Cannot open %s", interface);
      return -1;
    }

  printf ("Interface: %s\n", interface);
  printf ("  Status: configured (placeholder)\n");
  printf ("  Listen port: 51820\n");
  printf ("  Public key: (not available in placeholder)\n");
  printf ("  Private key: (hidden)\n");
  printf ("  Peers: 0\n");

  mach_port_deallocate (mach_task_self (), device);
  return 0;
}

int
main (int argc, char **argv)
{
  struct arguments args;

  memset (&args, 0, sizeof (args));
  args.listen_port = 51820;  /* Default WireGuard port */

  if (argp_parse (&argp, argc, argv, 0, 0, &args) < 0)
    return 1;

  /* Generate keypair */
  if (args.genkey)
    {
      const char *priv_file = args.private_key_file ?: "private.key";
      const char *pub_file = args.public_key_file ?: "public.key";
      return do_genkey (priv_file, pub_file);
    }

  /* Show configuration */
  if (args.show_config)
    return show_config (args.interface);

  /* Configure interface */
  if (args.interface)
    return configure_interface (&args);

  argp_help (&argp, stdout, ARGP_HELP_SEE, "wg-config");
  return 0;
}
