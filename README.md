# Padded ChaCha20 protocol for [ObfuscateWG](https://github.com/AlexSischin/obfuscate-wg)

## Overview

This protocol adds a padding to WireGuard packets and partially encrypts them with unauthenticated ChaCha20.
It uses a shared 256-bit secret key with a 96-bit nonce derived from the proxied packet. This approach
provides decent obfuscation while being moderately fast and having zero MTU overhead.
A possible downside is that it does not try to mimic any other protocol or application and may look unusual.

## Specification

### Structure

```text
 0                   1                   2                   3   
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
┌─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┐
│        nonce          │t│p│      other WireGuard headers      │ ┐
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤ │
¦                                                               ¦ ├─ S
¦                      WireGuard payload                        ¦ │
¦                                                               ¦ ┘
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
¦                                                               ¦ ┐
¦                           padding                             ¦ ├─ p
¦                                                               ¦ ┘
└─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┘
```

#### Nonce (12 bytes, unencrypted)

Nonce is derived from the original WireGuard packet.
WireGuard has 4 packet types, therefore this protocol has 4 different ways to derive a nonce:

##### Handshake request

```text
handshake_initiation {
    u8 message_type
    u8 reserved_zero[3]
    u32 sender_index
    u8 unencrypted_ephemeral[32]
    u8 encrypted_static[AEAD_LEN(32)]
    u8 encrypted_timestamp[AEAD_LEN(12)]
    u8 mac1[16]
    u8 mac2[16]
}
```

Where:
* `message_type` = 1
* nonce = `unencrypted_ephemeral[0:12]`

`unencrypted_ephemeral` is a `Curve25519` public key derived from a random secret key, meaning it is also random
for an outsider.

##### Handshake response

```text
handshake_response {
    u8 message_type
    u8 reserved_zero[3]
    u32 sender_index
    u32 receiver_index
    u8 unencrypted_ephemeral[32]
    u8 encrypted_nothing[AEAD_LEN(0)]
    u8 mac1[16]
    u8 mac2[16]
}
```

Where:
* `message_type` = 2
* nonce = `unencrypted_ephemeral[0:12]`

Similar to [Handshake request](#handshake-request).

##### Cookie reply

```text
packet_cookie_reply {
    u8 message_type
    u8 reserved_zero[3]
    u32 receiver_index
    u8 nonce[24]
    u8 encrypted_cookie[AEAD_LEN(16)]
}
```

Where:
* `message_type` = 3
* nonce = `nonce[0:12]`

`nonce` is random.

##### Data transfer

```text
packet_data {
    u8 message_type
    u8 reserved_zero[3]
    u32 receiver_index
    u64 counter
    u8 encrypted_encapsulated_packet[]
}
```

Where:
* `message_type` = 4
* nonce = `encrypted_encapsulated_packet[0:12]`

`encrypted_encapsulated_packet` is a `ChaCha20Poly1305`-encrypted payload, which is effectively random for an outsider.

#### t (1 byte, encrypted)

WireGuard packet type is preserved as-is.

#### p (1 byte, encrypted)

Padding size. Padding size is a pseudo-random value in range:

`0 <= p <= min(MTU + 32 - S, 255)`

, where MTU is the WireGuard MTU value, 32 is WireGuard overhead and `S` is the original WireGuard packet size.

It is deterministically derived from the amount of available space and the shared secret.
This means that the padding size is always the same for the packets of the same length,
which prevents the possibility to calculate the original packet size by averaging the padding out.

#### Other WireGuard headers (18 bytes, encrypted)

Other WireGuard headers are rearranged by preserved.

#### WireGuard payload (S-32 bytes, encrypted)

Preserved as-is. It is unneccessary to encrypt it, but it is encrypted for the sake of simplicity of the implementation.

#### Padding (p bytes, encrypted)

All zeroes. [More info](#p-1-byte).

