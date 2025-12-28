//! VMess AEAD Header Encryption
//!
//! Implements the AEAD header format used in VMess when alter_id = 0.

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes::Aes128;
use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
use crc32fast::Hasher as Crc32Hasher;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

type HmacSha256 = Hmac<Sha256>;

use crate::error::{Error, Result};

// KDF Salt Constants
pub const KDF_SALT_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
pub const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &str = "AES Auth ID Encryption";
pub const KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY: &str = "VMess Header AEAD Key";
pub const KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV: &str = "VMess Header AEAD Nonce";
pub const KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &str = "VMess Header AEAD Key_Length";
pub const KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &str = "VMess Header AEAD Nonce_Length";
pub const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &str = "AEAD Resp Header Len Key";
pub const KDF_SALT_AEAD_RESP_HEADER_LEN_IV: &str = "AEAD Resp Header Len IV";
pub const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &str = "AEAD Resp Header Key";
pub const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &str = "AEAD Resp Header IV";

const HMAC_BLOCK_SIZE: usize = 64; // SHA256 block size

/// Compute HMAC-SHA256
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hmac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC can take key of any size");
    hmac.update(data);
    let result = hmac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Process HMAC key: hash if > block size, pad with zeros if < block size
fn process_hmac_key(key: &[u8]) -> [u8; HMAC_BLOCK_SIZE] {
    let mut result = [0u8; HMAC_BLOCK_SIZE];
    if key.len() > HMAC_BLOCK_SIZE {
        // Hash the key using SHA256
        use sha2::Digest;
        let hash = sha2::Sha256::digest(key);
        result[..32].copy_from_slice(&hash);
    } else {
        result[..key.len()].copy_from_slice(key);
    }
    result
}

/// KDF (Key Derivation Function) using nested HMAC-SHA256
/// 
/// This implements v2ray's KDF which uses nested HMAC structure.
/// 
/// The Go implementation:
/// ```go
/// hmacf := hmac.New(sha256.New, KDF_SALT)
/// for _, v := range path {
///     hmacf = hmac.New(func() hash.Hash { return hmacf }, v)
/// }
/// hmacf.Write(key)
/// return hmacf.Sum(nil)
/// ```
/// 
/// When there's no path: HMAC-SHA256(KDF_SALT, key)
/// 
/// When there are paths, each path wraps the previous HMAC:
/// - path[0] wraps the base HMAC(KDF_SALT, ...)
/// - path[1] wraps the result of path[0]
/// - etc.
/// 
/// HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
/// When H is the inner HMAC, we recursively apply this formula.
pub fn kdf(key: &[u8], paths: &[&[u8]]) -> Vec<u8> {
    if paths.is_empty() {
        // Base case: just HMAC-SHA256(KDF_SALT, key)
        return hmac_sha256(KDF_SALT_VMESS_AEAD_KDF, key).to_vec();
    }
    
    // Process paths from last to first (outermost to innermost)
    // The last path is the outermost HMAC layer
    kdf_recursive(key, paths)
}

/// Recursive KDF implementation
/// 
/// For paths [p0, p1, p2], the structure is:
/// HMAC(p2, ..., HMAC(p1, ..., HMAC(p0, ..., HMAC(KDF_SALT, key))))
/// 
/// Where each HMAC uses the previous one as its hash function.
fn kdf_recursive(message: &[u8], paths: &[&[u8]]) -> Vec<u8> {
    if paths.is_empty() {
        // Base case: HMAC-SHA256(KDF_SALT, message)
        return hmac_sha256(KDF_SALT_VMESS_AEAD_KDF, message).to_vec();
    }
    
    // Get the last path (outermost layer) and remaining paths
    let last_path = paths[paths.len() - 1];
    let remaining = &paths[..paths.len() - 1];
    
    // Process the path as HMAC key
    let processed_key = process_hmac_key(last_path);
    
    // Create ipad and opad
    let mut ipad = [0x36u8; HMAC_BLOCK_SIZE];
    let mut opad = [0x5cu8; HMAC_BLOCK_SIZE];
    for i in 0..HMAC_BLOCK_SIZE {
        ipad[i] ^= processed_key[i];
        opad[i] ^= processed_key[i];
    }
    
    // inner = H(ipad || message) where H is the nested HMAC for remaining paths
    let mut inner_data = Vec::with_capacity(HMAC_BLOCK_SIZE + message.len());
    inner_data.extend_from_slice(&ipad);
    inner_data.extend_from_slice(message);
    let inner = kdf_recursive(&inner_data, remaining);
    
    // outer = H(opad || inner)
    let mut outer_data = Vec::with_capacity(HMAC_BLOCK_SIZE + 32);
    outer_data.extend_from_slice(&opad);
    outer_data.extend_from_slice(&inner);
    kdf_recursive(&outer_data, remaining)
}

/// KDF that returns 16 bytes
pub fn kdf16(key: &[u8], paths: &[&[u8]]) -> [u8; 16] {
    let result = kdf(key, paths);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result[..16]);
    out
}

/// Create Auth ID for AEAD header
pub fn create_auth_id(cmd_key: &[u8], timestamp: i64) -> [u8; 16] {
    let mut buf = Vec::with_capacity(16);

    // Write timestamp (8 bytes)
    buf.extend_from_slice(&timestamp.to_be_bytes());

    // Write 4 random bytes
    let mut random = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut random);
    buf.extend_from_slice(&random);

    // Calculate CRC32 checksum
    let mut hasher = Crc32Hasher::new();
    hasher.update(&buf);
    let checksum = hasher.finalize();
    buf.extend_from_slice(&checksum.to_be_bytes());

    // Encrypt with AES
    let aes_key = kdf16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY.as_bytes()]);
    let cipher = Aes128::new_from_slice(&aes_key).expect("Invalid key length");

    let mut result: [u8; 16] = buf.try_into().expect("buf must be 16 bytes");

    let block = aes::Block::from_mut_slice(&mut result);
    cipher.encrypt_block(block);

    result
}

/// Seal VMess AEAD header
pub fn seal_vmess_aead_header(cmd_key: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Protocol(format!("Time error: {}", e)))?
        .as_secs() as i64;

    debug!("VMess AEAD: timestamp={}", timestamp);

    let auth_id = create_auth_id(cmd_key, timestamp);
    debug!("VMess AEAD: auth_id={:02x?}", &auth_id);

    // Generate connection nonce (8 bytes)
    let mut connection_nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut connection_nonce);
    debug!("VMess AEAD: connection_nonce={:02x?}", &connection_nonce);

    // Encrypt payload length
    let payload_length = data.len() as u16;
    let length_bytes = payload_length.to_be_bytes();
    debug!("VMess AEAD: payload_length={}", payload_length);

    let length_key = kdf16(
        cmd_key,
        &[
            KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY.as_bytes(),
            &auth_id,
            &connection_nonce,
        ],
    );
    let length_iv = kdf(
        cmd_key,
        &[
            KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV.as_bytes(),
            &auth_id,
            &connection_nonce,
        ],
    );
    debug!("VMess AEAD length: key={:02x?}, iv={:02x?}", &length_key, &length_iv[..12]);

    let length_cipher = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;
    let length_nonce = Nonce::from_slice(&length_iv[..12]);

    let encrypted_length = length_cipher
        .encrypt(
            length_nonce,
            aes_gcm::aead::Payload {
                msg: &length_bytes,
                aad: &auth_id,
            },
        )
        .map_err(|e| Error::Crypto(format!("Encryption failed: {}", e)))?;
    debug!("VMess AEAD: encrypted_length ({} bytes)={:02x?}", encrypted_length.len(), &encrypted_length);

    // Encrypt payload
    let payload_key = kdf16(
        cmd_key,
        &[
            KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY.as_bytes(),
            &auth_id,
            &connection_nonce,
        ],
    );
    let payload_iv = kdf(
        cmd_key,
        &[
            KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV.as_bytes(),
            &auth_id,
            &connection_nonce,
        ],
    );
    debug!("VMess AEAD payload: key={:02x?}, iv={:02x?}", &payload_key, &payload_iv[..12]);

    let payload_cipher = Aes128Gcm::new_from_slice(&payload_key)
        .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;
    let payload_nonce = Nonce::from_slice(&payload_iv[..12]);

    let encrypted_payload = payload_cipher
        .encrypt(
            payload_nonce,
            aes_gcm::aead::Payload {
                msg: data,
                aad: &auth_id,
            },
        )
        .map_err(|e| Error::Crypto(format!("Encryption failed: {}", e)))?;
    debug!("VMess AEAD: encrypted_payload ({} bytes)", encrypted_payload.len());

    // Build output: auth_id (16) + encrypted_length (2+16) + nonce (8) + encrypted_payload
    let mut output = Vec::with_capacity(16 + 18 + 8 + encrypted_payload.len());
    output.extend_from_slice(&auth_id);
    output.extend_from_slice(&encrypted_length);
    output.extend_from_slice(&connection_nonce);
    output.extend_from_slice(&encrypted_payload);

    debug!("VMess AEAD: total output {} bytes (16 + 18 + 8 + {})", output.len(), encrypted_payload.len());

    Ok(output)
}

/// Decrypt AEAD response header length
pub fn open_aead_response_header(
    response_body_key: &[u8; 16],
    response_body_iv: &[u8; 16],
    encrypted_length: &[u8; 18],
) -> Result<u16> {
    let length_key = kdf16(
        response_body_key,
        &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY.as_bytes()],
    );
    let length_iv = kdf(
        response_body_iv,
        &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV.as_bytes()],
    );

    let cipher = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;
    let nonce = Nonce::from_slice(&length_iv[..12]);

    let decrypted = cipher
        .decrypt(nonce, encrypted_length.as_ref())
        .map_err(|e| Error::Crypto(format!("Decryption failed: {}", e)))?;

    if decrypted.len() < 2 {
        return Err(Error::Protocol("Invalid response header length".into()));
    }

    Ok(u16::from_be_bytes([decrypted[0], decrypted[1]]))
}

/// Decrypt AEAD response header payload
pub fn open_aead_response_payload(
    response_body_key: &[u8; 16],
    response_body_iv: &[u8; 16],
    encrypted_payload: &[u8],
) -> Result<Vec<u8>> {
    let payload_key = kdf16(
        response_body_key,
        &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY.as_bytes()],
    );
    let payload_iv = kdf(
        response_body_iv,
        &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV.as_bytes()],
    );

    let cipher = Aes128Gcm::new_from_slice(&payload_key)
        .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;
    let nonce = Nonce::from_slice(&payload_iv[..12]);

    cipher
        .decrypt(nonce, encrypted_payload)
        .map_err(|e| Error::Crypto(format!("Decryption failed: {}", e)))
}

// ============================================================================
// Server-side AEAD functions
// ============================================================================

/// Decrypt Auth ID and extract timestamp
/// Returns (timestamp, random_bytes) if valid
pub fn open_auth_id(cmd_key: &[u8], auth_id: &[u8; 16]) -> Result<i64> {
    use aes::cipher::BlockDecrypt;
    
    let aes_key = kdf16(cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY.as_bytes()]);
    let cipher = Aes128::new_from_slice(&aes_key)
        .map_err(|e| Error::Crypto(format!("Invalid key: {}", e)))?;
    
    let mut decrypted = *auth_id;
    let block = aes::Block::from_mut_slice(&mut decrypted);
    cipher.decrypt_block(block);
    
    // Verify CRC32
    let mut hasher = Crc32Hasher::new();
    hasher.update(&decrypted[..12]);
    let expected_crc = hasher.finalize();
    let actual_crc = u32::from_be_bytes([decrypted[12], decrypted[13], decrypted[14], decrypted[15]]);
    
    if expected_crc != actual_crc {
        return Err(Error::Crypto("Auth ID CRC mismatch".into()));
    }
    
    let timestamp = i64::from_be_bytes([
        decrypted[0], decrypted[1], decrypted[2], decrypted[3],
        decrypted[4], decrypted[5], decrypted[6], decrypted[7],
    ]);
    
    Ok(timestamp)
}

/// Decrypt VMess AEAD request header length
pub fn open_aead_request_header_length(
    cmd_key: &[u8],
    auth_id: &[u8; 16],
    connection_nonce: &[u8; 8],
    encrypted_length: &[u8; 18],
) -> Result<u16> {
    let length_key = kdf16(
        cmd_key,
        &[
            KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY.as_bytes(),
            auth_id,
            connection_nonce,
        ],
    );
    let length_iv = kdf(
        cmd_key,
        &[
            KDF_SALT_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV.as_bytes(),
            auth_id,
            connection_nonce,
        ],
    );

    let cipher = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;
    let nonce = Nonce::from_slice(&length_iv[..12]);

    let decrypted = cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: encrypted_length,
                aad: auth_id,
            },
        )
        .map_err(|e| Error::Crypto(format!("Header length decryption failed: {}", e)))?;

    if decrypted.len() < 2 {
        return Err(Error::Protocol("Invalid header length".into()));
    }

    Ok(u16::from_be_bytes([decrypted[0], decrypted[1]]))
}

/// Decrypt VMess AEAD request header payload
pub fn open_aead_request_header_payload(
    cmd_key: &[u8],
    auth_id: &[u8; 16],
    connection_nonce: &[u8; 8],
    encrypted_payload: &[u8],
) -> Result<Vec<u8>> {
    let payload_key = kdf16(
        cmd_key,
        &[
            KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_KEY.as_bytes(),
            auth_id,
            connection_nonce,
        ],
    );
    let payload_iv = kdf(
        cmd_key,
        &[
            KDF_SALT_VMESS_HEADER_PAYLOAD_AEAD_IV.as_bytes(),
            auth_id,
            connection_nonce,
        ],
    );

    let cipher = Aes128Gcm::new_from_slice(&payload_key)
        .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;
    let nonce = Nonce::from_slice(&payload_iv[..12]);

    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: encrypted_payload,
                aad: auth_id,
            },
        )
        .map_err(|e| Error::Crypto(format!("Header payload decryption failed: {}", e)))
}

/// Seal AEAD response header (server -> client)
pub fn seal_aead_response_header(
    response_body_key: &[u8; 16],
    response_body_iv: &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>> {
    // Encrypt length
    let length = data.len() as u16;
    let length_bytes = length.to_be_bytes();

    let length_key = kdf16(
        response_body_key,
        &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY.as_bytes()],
    );
    let length_iv = kdf(
        response_body_iv,
        &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV.as_bytes()],
    );

    let length_cipher = Aes128Gcm::new_from_slice(&length_key)
        .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;
    let length_nonce = Nonce::from_slice(&length_iv[..12]);

    let encrypted_length = length_cipher
        .encrypt(length_nonce, length_bytes.as_ref())
        .map_err(|e| Error::Crypto(format!("Length encryption failed: {}", e)))?;

    // Encrypt payload
    let payload_key = kdf16(
        response_body_key,
        &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY.as_bytes()],
    );
    let payload_iv = kdf(
        response_body_iv,
        &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV.as_bytes()],
    );

    let payload_cipher = Aes128Gcm::new_from_slice(&payload_key)
        .map_err(|e| Error::Crypto(format!("Failed to create cipher: {}", e)))?;
    let payload_nonce = Nonce::from_slice(&payload_iv[..12]);

    let encrypted_payload = payload_cipher
        .encrypt(payload_nonce, data)
        .map_err(|e| Error::Crypto(format!("Payload encryption failed: {}", e)))?;

    // Output: encrypted_length (18) + encrypted_payload
    let mut output = Vec::with_capacity(18 + encrypted_payload.len());
    output.extend_from_slice(&encrypted_length);
    output.extend_from_slice(&encrypted_payload);

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_no_path() {
        // Test case from Go/Python: KDF([]byte("test key")) with no path
        // Expected: e4389fc55d2b40befe2bfc5787a202916e0b57213465d55c5bedc08be576f2af
        let key = b"test key";
        let result = kdf(key, &[]);
        let hex_result: String = result.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex_result, "e4389fc55d2b40befe2bfc5787a202916e0b57213465d55c5bedc08be576f2af");
    }

    #[test]
    fn test_kdf_one_path() {
        // Test case from Python: KDF(b"test key", [b"path1"])
        // Expected: 274e0b9dacec4540b504cffbbd235394346da66ff89f8c1af2a10c62e27e1090
        let key = b"test key";
        let result = kdf(key, &[b"path1"]);
        let hex_result: String = result.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex_result, "274e0b9dacec4540b504cffbbd235394346da66ff89f8c1af2a10c62e27e1090");
    }

    #[test]
    fn test_kdf_two_paths() {
        // Test case from Python: KDF(b"test key", [b"path1", b"path2"])
        // Expected: 7b78473a74cb9f81d07befa35223da86e8de962c4ccf51a8d208b73bcd27cfd6
        let key = b"test key";
        let result = kdf(key, &[b"path1", b"path2"]);
        let hex_result: String = result.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex_result, "7b78473a74cb9f81d07befa35223da86e8de962c4ccf51a8d208b73bcd27cfd6");
    }

    #[test]
    fn test_kdf16_auth_id() {
        // Test case from Python: KDF16(b"test key", [b"AES Auth ID Encryption"])
        // Expected: 79a99739c76a37ab3f652841fbcf3cd0
        let key = b"test key";
        let result = kdf16(key, &[b"AES Auth ID Encryption"]);
        let hex_result: String = result.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex_result, "79a99739c76a37ab3f652841fbcf3cd0");
    }

    #[test]
    fn test_create_auth_id() {
        let cmd_key = [0u8; 16];
        let timestamp = 1234567890i64;
        let auth_id = create_auth_id(&cmd_key, timestamp);
        assert_eq!(auth_id.len(), 16);
    }
}
