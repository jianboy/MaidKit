import 'package:dartssh2/dartssh2.dart';

/// Algorithm preferences for every MaidKit SSH handshake.
///
/// dartssh2 4.x matches modern OpenSSH and drops SHA-1 host-key signatures
/// (`ssh-rsa`), SHA-1 key exchange, and CBC ciphers from its defaults. Many
/// older OpenSSH servers (and appliances) still offer only those, so the
/// system `ssh` client can connect after `HostKeyAlgorithms=+ssh-rsa` while
/// MaidKit would fail negotiation.
///
/// This list keeps dartssh2's modern order first, then appends the legacy
/// fallbacks that remain implemented in the library. Stronger algorithms are
/// still preferred whenever the server supports them.
///
/// `ssh-dss` is not available in dartssh2, so hosts that only present a DSA
/// host key still cannot connect.
const maidKitSshAlgorithms = SSHAlgorithms(
  kex: [
    SSHKexType.x25519Rfc,
    SSHKexType.x25519,
    SSHKexType.nistp521,
    SSHKexType.nistp384,
    SSHKexType.nistp256,
    SSHKexType.dhGexSha256,
    SSHKexType.dh14Sha256,
    SSHKexType.dhGexSha1,
    SSHKexType.dh14Sha1,
    SSHKexType.dh1Sha1,
  ],
  hostkey: [
    SSHHostkeyType.ed25519,
    SSHHostkeyType.rsaSha512,
    SSHHostkeyType.rsaSha256,
    SSHHostkeyType.ecdsa521,
    SSHHostkeyType.ecdsa384,
    SSHHostkeyType.ecdsa256,
    SSHHostkeyType.rsaSha1,
  ],
  cipher: [
    SSHCipherType.aes256gcm,
    SSHCipherType.aes128gcm,
    SSHCipherType.chacha20poly1305,
    SSHCipherType.aes256ctr,
    SSHCipherType.aes192ctr,
    SSHCipherType.aes128ctr,
    SSHCipherType.aes256cbc,
    SSHCipherType.aes192cbc,
    SSHCipherType.aes128cbc,
  ],
  mac: [
    SSHMacType.hmacSha256Etm,
    SSHMacType.hmacSha512Etm,
    SSHMacType.hmacSha256,
    SSHMacType.hmacSha512,
    SSHMacType.hmacSha1,
  ],
);
