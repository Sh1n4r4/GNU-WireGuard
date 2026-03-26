# WireGuard Support for GNU Hurd

This document describes the WireGuard VPN support implementation in the GNU Hurd lwIP network stack.

## Overview

WireGuard is a modern, fast, and secure VPN tunnel that uses state-of-the-art cryptography. This implementation integrates WireGuard as a network interface type in the Hurd's lwIP-based networking subsystem.

## Interface Naming

WireGuard interfaces are named with the prefix `wg` followed by a number:
- `/dev/wg0`
- `/dev/wg1`
- etc.

## Building with WireGuard Support

WireGuard support is built into the lwIP server by default. No additional configuration is needed.

## Usage

### Creating a WireGuard Interface

To create a WireGuard interface, set a translator on a device node:

```bash
# Create the device node
mknod /dev/wg0 c 10 200

# Set the lwip translator with WireGuard interface
settrans -c /dev/wg0 /hurd/lwip --interface=wg0
```

### Configuring WireGuard

WireGuard interfaces can be configured using the standard Hurd network configuration tools or programmatically through the interface's control port.

#### Example Configuration

A typical WireGuard configuration involves:

1. **Generate Keys**
   ```bash
   # Generate private key (keep this secret!)
   wg genkey > private.key
   
   # Generate public key from private key
   wg pubkey < private.key > public.key
   ```

2. **Configure the Interface**
   
   Example configuration structure:
   
   ```c
   struct wg_config config = {
     .listen_port = 51820,
     .private_key = { /* 32-byte private key */ },
     .peer_public_key = { /* 32-byte peer public key */ },
     .peer_endpoint = { .s_addr = inet_addr("192.168.1.100") },
     .peer_port = 51820,
   };
   ```

3. **Set IP Address**
   ```bash
   ifconfig wg0 10.0.0.1 netmask 255.255.255.0 up
   ```

## Architecture

### Files

- `lwip/port/include/netif/hurdwgif.h` - WireGuard interface header
- `lwip/port/netif/hurdwgif.c` - WireGuard interface implementation
- `lwip/port/netif/wg-crypto.h` - Cryptographic primitives header
- `lwip/port/netif/wg-crypto.c` - Cryptographic primitives implementation

### Components

1. **Interface Layer** (`hurdwgif.c`)
   - Implements the lwIP network interface callbacks
   - Handles packet encryption/decryption
   - Manages WireGuard handshakes

2. **Cryptographic Primitives** (`wg-crypto.c`)
   - **ChaCha20-Poly1305** for AEAD encryption
   - **Curve25519** for key exchange (ECDH)
   - **BLAKE2s** for hashing and KDF
   - Using **libgcrypt** for production-ready cryptography

3. **Control Interface**
   - Uses the trivfs framework for device control
   - Provides ioctls for configuration
   - Supports exclusive access control

### Data Flow

```
Application
    |
    v
lwIP Stack
    |
    v
WireGuard Interface (hurdwgif)
    |
    +---> ChaCha20-Poly1305 Encrypt/Decrypt
    |
    v
UDP Socket (Peer Communication)
```

### Cryptographic Details

**Encryption**: ChaCha20-Poly1305 AEAD
- 256-bit key
- 96-bit nonce (constructed from counter)
- 128-bit authentication tag

**Key Exchange**: Curve25519 ECDH
- 256-bit private/public keypairs
- Shared secret derivation

**Hashing**: BLAKE2s-256
- Key derivation function (KDF)
- Handshake hash computation

**Replay Protection**: 64-bit counter
- Monotonically increasing packet counter
- Rejects packets with old counters

## WireGuard Protocol

The implementation follows the WireGuard protocol specification:

- **Handshake Initiation** (Message Type 1)
- **Handshake Response** (Message Type 2)
- **Cookie Reply** (Message Type 3)
- **Data Transport** (Message Type 4)

## Limitations

### Current Implementation

1. **Single Peer**: Current implementation supports one peer per interface.

2. **No Keepalive**: Keepalive packets are not yet implemented.

3. **Limited IOCTL Support**: Configuration ioctls are minimal.

4. **Handshake Simplified**: Full Noise_IK handshake protocol needs completion.

### Future Enhancements

- [ ] Support multiple peers per interface
- [ ] Implement persistent keepalive
- [ ] Add comprehensive IOCTL interface
- [ ] Support for WireGuard configuration files
- [ ] NAT traversal support
- [ ] Roaming support (mobile clients)
- [ ] Complete Noise_IK handshake protocol

## Security Considerations

1. **Key Management**: Private keys must be stored securely and never transmitted.

2. **Access Control**: The interface supports exclusive access to prevent unauthorized configuration changes.

3. **Encryption**: All data packets are encrypted before transmission.

4. **Authentication**: Peer authentication through public key verification.

## Debugging

Enable debug output by compiling with:

```bash
CFLAGS += -DLWIP_DEBUG
```

Debug messages can be filtered using:

```bash
settrans -a /dev/wg0 --debug=netif
```

## Example: Setting Up a VPN Tunnel

### Server Side

```bash
# Create interface
mknod /dev/wg0 c 10 200
settrans -c /dev/wg0 /hurd/lwip --interface=wg0

# Configure IP
ifconfig wg0 10.0.0.1 netmask 255.255.255.0 up

# Configure WireGuard (programmatic)
# See wg-config tool for configuration
```

### Client Side

```bash
# Create interface
mknod /dev/wg0 c 10 200
settrans -c /dev/wg0 /hurd/lwip --interface=wg0

# Configure IP
ifconfig wg0 10.0.0.2 netmask 255.255.255.0 up

# Set default route
route add default gw 10.0.0.1
```

## API Reference

### Core Functions

- `hurdwgif_module_init()` - Initialize WireGuard module
- `hurdwgif_device_init()` - Initialize a WireGuard network interface
- `hurdwgif_configure()` - Configure interface with WireGuard parameters
- `hurdwgif_get_config()` - Retrieve current configuration

### Configuration Functions

- `hurdwgif_set_private_key()` - Set the private key
- `hurdwgif_set_peer_public_key()` - Set peer's public key
- `hurdwgif_set_preshared_key()` - Set optional preshared key
- `hurdwgif_add_peer()` - Add a peer with endpoint

## Troubleshooting

### Interface Won't Start

1. Check if the lwIP server is running
2. Verify the device node exists
3. Check system logs for error messages

### Handshake Fails

1. Verify both sides have correct public keys
2. Check firewall rules allow UDP port 51820
3. Ensure endpoints are reachable

### No Data Transfer

1. Verify routing table configuration
2. Check MTU settings (should be ≤ 1420 for WireGuard)
3. Verify peer configuration on both ends

## License

This implementation is part of the GNU Hurd and is licensed under the GNU General Public License version 2 or later.

## References

- [WireGuard Protocol Specification](https://www.wireguard.com/protocol/)
- [GNU Hurd Networking](https://www.gnu.org/software/hurd/)
- [lwIP Documentation](https://savannah.nongnu.org/projects/lwip/)

## Contact

For bugs and feature requests, please contact <bug-hurd@gnu.org>.
