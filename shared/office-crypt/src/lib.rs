//! Password-protected Office files (Word, Excel, PowerPoint): ECMA-376 document encryption,
//! written from Microsoft's public Open Specification [MS-OFFCRYPTO]. Read: the *agile* method
//! (Office 2010 and later, §2.3.4.10–§2.3.4.15) and the *standard* one (Office 2007, §2.3.4.5–
//! §2.3.4.9). Written: agile, with the data-spaces streams of §2.1 / §2.3.4.1–§2.3.4.3.
//!
//! An encrypted package is not a zip but an OLE compound file ([MS-CFB]) holding
//! `EncryptionInfo` (how the key is derived from the password, as XML) and `EncryptedPackage`
//! (the original zip, AES-CBC encrypted in 4096-byte segments). A random *intermediate key*
//! encrypts the package; the password, hashed `spinCount` times with a salt, encrypts that key and
//! a verifier that tells a wrong password apart; an HMAC over the encrypted stream checks that it
//! hasn't been damaged or tampered with.
//!
//! Files are hostile: every stream read is capped, every length is checked before slicing, and the
//! spin count is bounded by the specification's maximum. Passwords and keys are wiped from memory
//! when dropped ([`Zeroizing`]) and never logged.

use std::io::{Cursor, Read, Write};

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use base64::Engine as _;
use hmac::Mac;
use sha2::Digest;
use zeroize::Zeroizing;

/// Why a file couldn't be decrypted (or encrypted).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptError {
    /// The file is encrypted and no password was given.
    #[error("{}", PASSWORD_REQUIRED)]
    PasswordRequired,
    /// The password doesn't open the file.
    #[error("{}", WRONG_PASSWORD)]
    WrongPassword,
    /// The file is encrypted in a way this can't read, or its encryption data is damaged (or
    /// encrypting failed).
    #[error("{0}")]
    Invalid(String),
    /// A stream is larger than allowed.
    #[error("{0}")]
    Limit(String),
}

/// What [`CryptError::PasswordRequired`] says.
pub const PASSWORD_REQUIRED: &str = "this file is protected with a password";
/// What [`CryptError::WrongPassword`] says.
pub const WRONG_PASSWORD: &str = "the password is incorrect";

/// A file's password: wiped from memory when dropped, never printed (`Debug` shows `***`).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Password(Zeroizing<String>);

impl Password {
    pub fn new(s: &str) -> Password {
        Password(Zeroizing::new(s.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// The text, for a password box to edit in place.
    pub fn as_mut_string(&mut self) -> &mut String {
        &mut self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password(***)")
    }
}

/// The password Excel encrypts a workbook with when none was set (a workbook saved
/// "read-only recommended" or with only a password to modify): it opens without asking.
const DEFAULT_PASSWORD: &str = "VelvetSweatshop";

/// The spin count Word uses, and VDoc writes.
pub const DEFAULT_SPIN_COUNT: u32 = 100_000;
/// The largest spin count the specification allows (§2.3.4.10 `ST_SpinCount`): it bounds the
/// work a hostile file can ask for.
const MAX_SPIN_COUNT: u32 = 10_000_000;
/// Word's limit on password length, in characters.
pub const MAX_PASSWORD_CHARS: usize = 255;
/// `EncryptedPackage` is encrypted in segments of this many bytes (§2.3.4.15).
const SEGMENT: usize = 4096;
/// Largest `EncryptionInfo` stream read (the XML is a few kilobytes).
const MAX_INFO: u64 = 1 << 20;
/// AES's block size.
const BLOCK: usize = 16;
/// Salt length written.
const SALT: usize = 16;

/// Block keys (§2.3.4.13, §2.3.4.14).
const BK_VERIFIER_INPUT: [u8; 8] = [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79];
const BK_VERIFIER_VALUE: [u8; 8] = [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e];
const BK_KEY_VALUE: [u8; 8] = [0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6];
const BK_HMAC_KEY: [u8; 8] = [0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6];
const BK_HMAC_VALUE: [u8; 8] = [0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33];

/// An OLE compound file starts with these bytes ([MS-CFB] §2.2).
const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

const NS_ENCRYPTION: &str = "http://schemas.microsoft.com/office/2006/encryption";
const NS_PASSWORD: &str = "http://schemas.microsoft.com/office/2006/keyEncryptor/password";

/// Is this an encrypted Office package (a compound file with `EncryptionInfo` and
/// `EncryptedPackage` streams) rather than a zip?
pub fn is_encrypted(bytes: &[u8]) -> bool {
    if bytes.get(..8) != Some(&CFB_MAGIC[..]) {
        return false;
    }
    match cfb::CompoundFile::open(Cursor::new(bytes)) {
        Ok(comp) => comp.is_stream("/EncryptionInfo") && comp.is_stream("/EncryptedPackage"),
        Err(_) => false,
    }
}

/// The zip package inside an encrypted Office file. Without a password (`None`) this says
/// [`CryptError::PasswordRequired`] once it knows the file is one it can decrypt; a password that
/// doesn't fit gives [`CryptError::WrongPassword`].
pub fn decrypt(bytes: &[u8], password: Option<&str>) -> Result<Vec<u8>, CryptError> {
    let mut comp = cfb::CompoundFile::open(Cursor::new(bytes)).map_err(|e| bad(format!("not a readable compound file ({e})")))?;
    let info = stream(&mut comp, "/EncryptionInfo", MAX_INFO)?;
    let package = stream(&mut comp, "/EncryptedPackage", bytes.len() as u64)?;
    if is_standard(&info) {
        let info = parse_standard(&info)?;
        return match password {
            Some(p) => decrypt_standard(&info, p, &package),
            // Excel's own password first: a workbook that has no other opens without asking
            None => decrypt_standard(&info, DEFAULT_PASSWORD, &package).map_err(|e| match e {
                CryptError::WrongPassword => CryptError::PasswordRequired,
                e => e,
            }),
        };
    }
    let info = parse_info(&info)?;
    let Some(password) = password else {
        return match decrypt_agile(&info, DEFAULT_PASSWORD, &package) {
            Err(CryptError::WrongPassword) => Err(CryptError::PasswordRequired),
            r => r,
        };
    };
    decrypt_agile(&info, password, &package)
}

fn decrypt_agile(info: &Info, password: &str, package: &[u8]) -> Result<Vec<u8>, CryptError> {
    let pe = &info.password;
    let hn = iterate(pe.hash, &pe.salt, password, pe.spin_count);
    // The verifier (§2.3.4.13): a random value and its hash, both encrypted with keys derived
    // from the password. They match only for the right password.
    let key_input = derive_key(pe.hash, &hn, &BK_VERIFIER_INPUT, pe.key_bytes);
    let key_value = derive_key(pe.hash, &hn, &BK_VERIFIER_VALUE, pe.key_bytes);
    let iv = make_iv(pe.hash, &pe.salt, None, pe.block_size);
    let input = Zeroizing::new(cbc_decrypt(&key_input, &iv, &pe.verifier_input)?);
    let input = input.get(..pe.salt_size).ok_or_else(|| bad("the password verifier is too short"))?;
    let value = Zeroizing::new(cbc_decrypt(&key_value, &iv, &pe.verifier_hash)?);
    let value = value.get(..pe.hash.size()).ok_or_else(|| bad("the password verifier hash is too short"))?;
    if !same(&pe.hash.hash(&[input]), value) {
        return Err(CryptError::WrongPassword);
    }
    // The intermediate key that encrypts the package.
    let key_key = derive_key(pe.hash, &hn, &BK_KEY_VALUE, pe.key_bytes);
    let key = Zeroizing::new(cbc_decrypt(&key_key, &iv, &pe.key_value)?);
    let key = Zeroizing::new(key.get(..info.key_bytes).ok_or_else(|| bad("the encrypted key is too short"))?.to_vec());
    // Data integrity (§2.3.4.14): an HMAC of the whole EncryptedPackage stream.
    if let Some((enc_key, enc_value)) = &info.integrity {
        let hmac_key = Zeroizing::new(cbc_decrypt(&key, &make_iv(info.hash, &info.salt, Some(&BK_HMAC_KEY), info.block_size), enc_key)?);
        // The key is the salt, zero-padded to the block size; HMAC pads short keys with zeros
        // anyway, so the padded key gives the same HMAC.
        let hmac_key = hmac_key.get(..hmac_key.len().min(info.hash.size())).unwrap_or(&[]);
        let expected = cbc_decrypt(&key, &make_iv(info.hash, &info.salt, Some(&BK_HMAC_VALUE), info.block_size), enc_value)?;
        let expected = expected.get(..info.hash.size()).ok_or_else(|| bad("the integrity check value is too short"))?;
        if !same(&info.hash.hmac(hmac_key, package)?, expected) {
            return Err(bad("the document is damaged (its integrity check failed)"));
        }
    }
    // The package itself (§2.3.4.15): StreamSize, then 4096-byte segments, each with its own IV.
    let size = package
        .get(..8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| bad("the encrypted package is truncated"))?;
    let data = package.get(8..).unwrap_or(&[]);
    let size = usize::try_from(size).ok().filter(|s| *s <= data.len()).ok_or_else(|| bad("the encrypted package is truncated"))?;
    let needed = size.div_ceil(BLOCK).saturating_mul(BLOCK);
    let data = data.get(..needed).ok_or_else(|| bad("the encrypted package is truncated"))?;
    let mut out = Vec::with_capacity(needed);
    for (i, seg) in data.chunks(SEGMENT).enumerate() {
        let i = u32::try_from(i).map_err(|_| bad("the encrypted package is too large"))?;
        let iv = make_iv(info.hash, &info.salt, Some(&i.to_le_bytes()), info.block_size);
        out.extend_from_slice(&cbc_decrypt(&key, &iv, seg)?);
    }
    out.truncate(size);
    Ok(out)
}

/// Encrypt a zip package with `password` (agile encryption: AES-256-CBC, SHA-512, Word's spin
/// count), as Word's "Encrypt with Password" does.
pub fn encrypt(package: &[u8], password: &str) -> Result<Vec<u8>, CryptError> {
    encrypt_with_spin_count(package, password, DEFAULT_SPIN_COUNT)
}

/// [`encrypt`] with a chosen spin count (tests use a small one; files should use the default).
pub fn encrypt_with_spin_count(package: &[u8], password: &str, spin_count: u32) -> Result<Vec<u8>, CryptError> {
    check_password(password)?;
    let spin_count = spin_count.min(MAX_SPIN_COUNT);
    let hash = Hash::Sha512;
    let key_bytes = 32;
    let key_data_salt = random(SALT)?;
    let password_salt = random(SALT)?;
    let key = random(key_bytes)?;
    let verifier = random(SALT)?;
    // The HMAC key is a salt as long as the hash (MS-OFFCRYPTO §2.3.4.14).
    let hmac_salt = random(hash.size())?;

    // The package, segment by segment; the last segment is zero-padded to the block size.
    let mut stream = Vec::with_capacity(package.len().saturating_add(8 + BLOCK));
    stream.extend_from_slice(&(package.len() as u64).to_le_bytes());
    for (i, seg) in package.chunks(SEGMENT).enumerate() {
        let i = u32::try_from(i).map_err(|_| bad("the document is too large to encrypt"))?;
        let iv = make_iv(hash, &key_data_salt, Some(&i.to_le_bytes()), BLOCK);
        stream.extend_from_slice(&cbc_encrypt(&key, &iv, &padded(seg))?);
    }

    // The password key encryptor (§2.3.4.13).
    let hn = iterate(hash, &password_salt, password, spin_count);
    let iv = make_iv(hash, &password_salt, None, BLOCK);
    let enc_verifier_input = cbc_encrypt(&derive_key(hash, &hn, &BK_VERIFIER_INPUT, key_bytes), &iv, &padded(&verifier))?;
    let enc_verifier_hash = cbc_encrypt(&derive_key(hash, &hn, &BK_VERIFIER_VALUE, key_bytes), &iv, &padded(&hash.hash(&[&verifier])))?;
    let enc_key_value = cbc_encrypt(&derive_key(hash, &hn, &BK_KEY_VALUE, key_bytes), &iv, &padded(&key))?;

    // Data integrity (§2.3.4.14).
    let enc_hmac_key = cbc_encrypt(&key, &make_iv(hash, &key_data_salt, Some(&BK_HMAC_KEY), BLOCK), &padded(&hmac_salt))?;
    let hmac = hash.hmac(&hmac_salt, &stream)?;
    let enc_hmac_value = cbc_encrypt(&key, &make_iv(hash, &key_data_salt, Some(&BK_HMAC_VALUE), BLOCK), &padded(&hmac))?;

    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let params = format!(
        r#"saltSize="{SALT}" blockSize="{BLOCK}" keyBits="{}" hashSize="{}" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="{}""#,
        key_bytes * 8,
        hash.size(),
        hash.name(),
    );
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n\
         <encryption xmlns=\"{NS_ENCRYPTION}\" xmlns:p=\"{NS_PASSWORD}\">\
         <keyData {params} saltValue=\"{}\"/>\
         <dataIntegrity encryptedHmacKey=\"{}\" encryptedHmacValue=\"{}\"/>\
         <keyEncryptors><keyEncryptor uri=\"{NS_PASSWORD}\">\
         <p:encryptedKey spinCount=\"{spin_count}\" {params} saltValue=\"{}\" encryptedVerifierHashInput=\"{}\" encryptedVerifierHashValue=\"{}\" encryptedKeyValue=\"{}\"/>\
         </keyEncryptor></keyEncryptors></encryption>",
        b64(&key_data_salt),
        b64(&enc_hmac_key),
        b64(&enc_hmac_value),
        b64(&password_salt),
        b64(&enc_verifier_input),
        b64(&enc_verifier_hash),
        b64(&enc_key_value),
    );
    // EncryptionInfo (§2.3.4.10): version 4.4, reserved 0x40, the XML.
    let mut info = vec![4, 0, 4, 0, 0x40, 0, 0, 0];
    info.extend_from_slice(xml.as_bytes());

    let io = |e: std::io::Error| bad(format!("couldn't write the compound file ({e})"));
    let mut comp = cfb::CompoundFile::create_with_version(cfb::Version::V3, Cursor::new(Vec::new())).map_err(io)?;
    for (path, data) in [
        ("/\u{6}DataSpaces/Version", data_space_version()),
        ("/\u{6}DataSpaces/DataSpaceMap", data_space_map()),
        ("/\u{6}DataSpaces/DataSpaceInfo/StrongEncryptionDataSpace", data_space_definition()),
        ("/\u{6}DataSpaces/TransformInfo/StrongEncryptionTransform/\u{6}Primary", primary_transform()),
        ("/EncryptionInfo", info),
        ("/EncryptedPackage", stream),
    ] {
        if let Some((parent, _)) = path.rsplit_once('/')
            && !parent.is_empty()
        {
            comp.create_storage_all(parent).map_err(io)?;
        }
        comp.create_stream(path).map_err(io)?.write_all(&data).map_err(io)?;
    }
    comp.flush().map_err(io)?;
    Ok(comp.into_inner().into_inner())
}

/// Refuse a password Word wouldn't accept: empty, or longer than [`MAX_PASSWORD_CHARS`].
pub fn check_password(password: &str) -> Result<(), CryptError> {
    if password.is_empty() {
        return Err(bad("the password is empty"));
    }
    if password.chars().count() > MAX_PASSWORD_CHARS {
        return Err(bad(format!("passwords are at most {MAX_PASSWORD_CHARS} characters")));
    }
    Ok(())
}

fn bad(msg: impl Into<String>) -> CryptError {
    CryptError::Invalid(msg.into())
}

/// A root-level stream, at most `cap` bytes.
fn stream<F: Read + std::io::Seek>(comp: &mut cfb::CompoundFile<F>, path: &str, cap: u64) -> Result<Vec<u8>, CryptError> {
    let s = comp.open_stream(path).map_err(|e| bad(format!("can't read {} ({e})", path.trim_start_matches('/'))))?;
    let mut v = Vec::new();
    s.take(cap.saturating_add(1)).read_to_end(&mut v).map_err(|e| bad(format!("can't read {} ({e})", path.trim_start_matches('/'))))?;
    if v.len() as u64 > cap {
        return Err(CryptError::Limit(format!("{} is too large", path.trim_start_matches('/'))));
    }
    Ok(v)
}

/// The hash algorithms agile encryption names that VDoc supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn parse(s: &str) -> Option<Hash> {
        match s.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Some(Hash::Sha1),
            "SHA256" => Some(Hash::Sha256),
            "SHA384" => Some(Hash::Sha384),
            "SHA512" => Some(Hash::Sha512),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Hash::Sha1 => "SHA-1",
            Hash::Sha256 => "SHA256",
            Hash::Sha384 => "SHA384",
            Hash::Sha512 => "SHA512",
        }
    }

    fn size(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    /// The hash of the concatenated `parts`.
    fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        fn go<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            d.finalize().to_vec()
        }
        match self {
            Hash::Sha1 => go::<sha1::Sha1>(parts),
            Hash::Sha256 => go::<sha2::Sha256>(parts),
            Hash::Sha384 => go::<sha2::Sha384>(parts),
            Hash::Sha512 => go::<sha2::Sha512>(parts),
        }
    }

    fn hmac(self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptError> {
        fn go<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptError> {
            let mut m = <M as KeyInit>::new_from_slice(key).map_err(|_| bad("bad integrity key"))?;
            m.update(msg);
            Ok(m.finalize().into_bytes().to_vec())
        }
        match self {
            Hash::Sha1 => go::<hmac::Hmac<sha1::Sha1>>(key, msg),
            Hash::Sha256 => go::<hmac::Hmac<sha2::Sha256>>(key, msg),
            Hash::Sha384 => go::<hmac::Hmac<sha2::Sha384>>(key, msg),
            Hash::Sha512 => go::<hmac::Hmac<sha2::Sha512>>(key, msg),
        }
    }
}

/// The password hash after `spin_count` iterations (§2.3.4.11): H0 = H(salt + password as
/// UTF-16LE), Hn = H(iterator + Hn-1).
fn iterate(hash: Hash, salt: &[u8], password: &str, spin_count: u32) -> Zeroizing<Vec<u8>> {
    let pw: Zeroizing<Vec<u8>> = Zeroizing::new(password.encode_utf16().flat_map(u16::to_le_bytes).collect());
    let mut h = Zeroizing::new(hash.hash(&[salt, &pw]));
    for i in 0..spin_count.min(MAX_SPIN_COUNT) {
        *h = hash.hash(&[&i.to_le_bytes(), &h]);
    }
    h
}

/// A key from the iterated password hash and a block key (§2.3.4.11): H(Hn + blockKey),
/// truncated to `len`, or padded with 0x36.
fn derive_key(hash: Hash, hn: &[u8], block_key: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut k = Zeroizing::new(hash.hash(&[hn, block_key]));
    k.resize(len, 0x36);
    k
}

/// An initialization vector (§2.3.4.12): H(salt + blockKey), or the salt itself, truncated to
/// the block size or padded with 0x36.
fn make_iv(hash: Hash, salt: &[u8], block_key: Option<&[u8]>, block_size: usize) -> Vec<u8> {
    let mut iv = match block_key {
        Some(b) => hash.hash(&[salt, b]),
        None => salt.to_vec(),
    };
    iv.resize(block_size, 0x36);
    iv
}

/// `data` zero-padded to a whole number of blocks.
fn padded(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(data.to_vec());
    v.resize(data.len().div_ceil(BLOCK).saturating_mul(BLOCK), 0);
    v
}

fn random(n: usize) -> Result<Zeroizing<Vec<u8>>, CryptError> {
    let mut v = Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut v).map_err(|e| bad(format!("no secure random numbers available ({e})")))?;
    Ok(v)
}

/// Compare without stopping at the first difference.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// AES with a 128-, 192- or 256-bit key.
enum Aes {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl Aes {
    fn new(key: &[u8]) -> Result<Aes, CryptError> {
        let err = |_| bad("bad AES key");
        Ok(match key.len() {
            16 => Aes::A128(aes::Aes128::new_from_slice(key).map_err(err)?),
            24 => Aes::A192(aes::Aes192::new_from_slice(key).map_err(err)?),
            32 => Aes::A256(aes::Aes256::new_from_slice(key).map_err(err)?),
            n => return Err(bad(format!("unsupported AES key length {} bits", n * 8))),
        })
    }

    fn encrypt(&self, b: &mut aes::Block) {
        match self {
            Aes::A128(c) => c.encrypt_block(b),
            Aes::A192(c) => c.encrypt_block(b),
            Aes::A256(c) => c.encrypt_block(b),
        }
    }

    fn decrypt(&self, b: &mut aes::Block) {
        match self {
            Aes::A128(c) => c.decrypt_block(b),
            Aes::A192(c) => c.decrypt_block(b),
            Aes::A256(c) => c.decrypt_block(b),
        }
    }
}

/// AES-CBC without padding: `data` must be whole blocks.
fn cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptError> {
    let aes = Aes::new(key)?;
    let (blocks, rest) = data.as_chunks::<BLOCK>();
    let mut prev: [u8; BLOCK] = iv.try_into().map_err(|_| bad("bad initialization vector"))?;
    if !rest.is_empty() {
        return Err(bad("encrypted data isn't a whole number of blocks"));
    }
    let mut out = Vec::with_capacity(data.len());
    for b in blocks {
        let mut x = aes::Block::default();
        for ((o, p), v) in x.iter_mut().zip(b).zip(&prev) {
            *o = p ^ v;
        }
        aes.encrypt(&mut x);
        prev.copy_from_slice(&x);
        out.extend_from_slice(&x);
    }
    Ok(out)
}

/// AES-CBC decryption without padding.
fn cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptError> {
    let aes = Aes::new(key)?;
    let (blocks, rest) = data.as_chunks::<BLOCK>();
    if !rest.is_empty() {
        return Err(bad("encrypted data isn't a whole number of blocks"));
    }
    let mut prev: [u8; BLOCK] = iv.try_into().map_err(|_| bad("bad initialization vector"))?;
    let mut out = Vec::with_capacity(data.len());
    for b in blocks {
        let mut x = aes::Block::default();
        x.copy_from_slice(b);
        aes.decrypt(&mut x);
        for (o, v) in x.iter_mut().zip(&prev) {
            *o ^= v;
        }
        prev = *b;
        out.extend_from_slice(&x);
    }
    Ok(out)
}

/// What `EncryptionInfo` says.
struct Info {
    hash: Hash,
    salt: Vec<u8>,
    block_size: usize,
    key_bytes: usize,
    /// encryptedHmacKey, encryptedHmacValue.
    integrity: Option<(Vec<u8>, Vec<u8>)>,
    password: PasswordEncryptor,
}

struct PasswordEncryptor {
    hash: Hash,
    salt: Vec<u8>,
    salt_size: usize,
    block_size: usize,
    key_bytes: usize,
    spin_count: u32,
    verifier_input: Vec<u8>,
    verifier_hash: Vec<u8>,
    key_value: Vec<u8>,
}

/// Cipher parameters shared by `keyData` and `encryptedKey`.
struct Params {
    hash: Hash,
    salt: Vec<u8>,
    salt_size: usize,
    block_size: usize,
    key_bytes: usize,
}

fn parse_info(info: &[u8]) -> Result<Info, CryptError> {
    let (major, minor) = match info.get(..4) {
        Some([a, b, c, d]) => (u16::from_le_bytes([*a, *b]), u16::from_le_bytes([*c, *d])),
        _ => return Err(bad("EncryptionInfo is truncated")),
    };
    match (major, minor) {
        (4, 4) => {}
        (3 | 4, 3) => return Err(bad("this file uses extensible encryption, which can't be opened")),
        _ => return Err(bad(format!("unknown encryption version {major}.{minor}"))),
    }
    let els = elements(info.get(8..).unwrap_or(&[]))?;
    if els.first().map(|e| e.local.as_str()) != Some("encryption") {
        return Err(bad("EncryptionInfo has no <encryption> element"));
    }
    let key_data = els.iter().find(|e| e.local == "keyData").ok_or_else(|| bad("EncryptionInfo has no keyData"))?;
    let kd = params(key_data)?;
    let integrity = match els.iter().find(|e| e.local == "dataIntegrity") {
        Some(di) => Some((b64_attr(di, "encryptedHmacKey")?, b64_attr(di, "encryptedHmacValue")?)),
        None => None,
    };
    // The password key encryptor is the `encryptedKey` with a spin count (a certificate key
    // encryptor has none).
    if !els.iter().any(|e| e.local == "keyEncryptors") {
        return Err(bad("EncryptionInfo has no keyEncryptors"));
    }
    let ek = els
        .iter()
        .find(|e| e.local == "encryptedKey" && e.attr("spinCount").is_some())
        .ok_or_else(|| bad("this file isn't protected with a password (only certificate encryption is listed)"))?;
    let pe = params(ek)?;
    let spin_count: u32 = ek.attr("spinCount").and_then(|s| s.trim().parse().ok()).ok_or_else(|| bad("bad spinCount"))?;
    if spin_count > MAX_SPIN_COUNT {
        return Err(bad(format!("spinCount {spin_count} is over the allowed maximum")));
    }
    Ok(Info {
        hash: kd.hash,
        salt: kd.salt,
        block_size: kd.block_size,
        key_bytes: kd.key_bytes,
        integrity,
        password: PasswordEncryptor {
            hash: pe.hash,
            salt: pe.salt,
            salt_size: pe.salt_size,
            block_size: pe.block_size,
            key_bytes: pe.key_bytes,
            spin_count,
            verifier_input: b64_attr(ek, "encryptedVerifierHashInput")?,
            verifier_hash: b64_attr(ek, "encryptedVerifierHashValue")?,
            key_value: b64_attr(ek, "encryptedKeyValue")?,
        },
    })
}

fn params(e: &XmlEl) -> Result<Params, CryptError> {
    let num =
        |k: &str| -> Result<usize, CryptError> { e.attr(k).and_then(|s| s.trim().parse::<usize>().ok()).ok_or_else(|| bad(format!("bad {k}"))) };
    let cipher = e.attr("cipherAlgorithm").unwrap_or("");
    if !cipher.eq_ignore_ascii_case("AES") {
        return Err(bad(format!("the {cipher:?} cipher isn't supported")));
    }
    let chaining = e.attr("cipherChaining").unwrap_or("");
    if chaining != "ChainingModeCBC" {
        return Err(bad(format!("the {chaining:?} chaining mode isn't supported")));
    }
    let name = e.attr("hashAlgorithm").unwrap_or("");
    let hash = Hash::parse(name).ok_or_else(|| bad(format!("the {name:?} hash algorithm isn't supported")))?;
    if num("hashSize")? != hash.size() {
        return Err(bad("hashSize doesn't match the hash algorithm"));
    }
    let block_size = num("blockSize")?;
    if block_size != BLOCK {
        return Err(bad(format!("AES needs a block size of {BLOCK}, not {block_size}")));
    }
    let key_bits = num("keyBits")?;
    if !matches!(key_bits, 128 | 192 | 256) {
        return Err(bad(format!("unsupported AES key size {key_bits}")));
    }
    let salt = b64_attr(e, "saltValue")?;
    let salt_size = num("saltSize")?;
    if salt.is_empty() || salt.len() != salt_size {
        return Err(bad("the salt doesn't match saltSize"));
    }
    Ok(Params { hash, salt, salt_size, block_size, key_bytes: key_bits / 8 })
}

fn b64_attr(e: &XmlEl, k: &str) -> Result<Vec<u8>, CryptError> {
    let s = e.attr(k).ok_or_else(|| bad(format!("{k} is missing")))?;
    let s: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|_| bad(format!("{k} isn't valid base64")))
}

/// A UNICODE-LP-P4 string (§2.1.2): byte length, UTF-16LE, zero-padded to 4 bytes.
fn lp_p4(out: &mut Vec<u8>, s: &str) {
    let units: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend_from_slice(&(units.len() as u32).to_le_bytes());
    out.extend_from_slice(&units);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// `\x06DataSpaces\Version` (§2.1.5).
fn data_space_version() -> Vec<u8> {
    let mut v = Vec::new();
    lp_p4(&mut v, "Microsoft.Container.DataSpaces");
    for _ in 0..3 {
        v.extend_from_slice(&[1, 0, 0, 0]);
    }
    v
}

/// `\x06DataSpaces\DataSpaceMap` (§2.1.6, §2.3.4.1): EncryptedPackage → StrongEncryptionDataSpace.
fn data_space_map() -> Vec<u8> {
    let mut entry = Vec::new();
    entry.extend_from_slice(&1u32.to_le_bytes());
    entry.extend_from_slice(&0u32.to_le_bytes());
    lp_p4(&mut entry, "EncryptedPackage");
    lp_p4(&mut entry, "StrongEncryptionDataSpace");
    let mut v = Vec::new();
    v.extend_from_slice(&8u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&((entry.len() + 4) as u32).to_le_bytes());
    v.extend_from_slice(&entry);
    v
}

/// `\x06DataSpaces\DataSpaceInfo\StrongEncryptionDataSpace` (§2.1.7, §2.3.4.2).
fn data_space_definition() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&8u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    lp_p4(&mut v, "StrongEncryptionTransform");
    v
}

/// `\x06DataSpaces\TransformInfo\StrongEncryptionTransform\x06Primary` (§2.1.8, §2.1.9,
/// §2.3.4.3): the encryption transform, with a null EncryptionName as agile encryption requires.
fn primary_transform() -> Vec<u8> {
    let mut id = Vec::new();
    lp_p4(&mut id, "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}");
    let mut v = Vec::new();
    // TransformLength: the bytes before TransformName.
    v.extend_from_slice(&((8 + id.len()) as u32).to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&id);
    lp_p4(&mut v, "Microsoft.Container.EncryptionTransform");
    for _ in 0..3 {
        v.extend_from_slice(&[1, 0, 0, 0]);
    }
    // EncryptionTransformInfo: null name, block size, cipher mode 0, reserved 4.
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&(BLOCK as u32).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&4u32.to_le_bytes());
    v
}

/// An element of `EncryptionInfo`'s XML: its local name and attributes (by local name).
struct XmlEl {
    local: String,
    attrs: Vec<(String, String)>,
}

impl XmlEl {
    fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
}

/// Every element of the XML, in document order. The values read are numbers, names and base64,
/// which have nothing to unescape.
fn elements(xml: &[u8]) -> Result<Vec<XmlEl>, CryptError> {
    let mut r = quick_xml::Reader::from_reader(xml);
    let mut out = Vec::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(e) | quick_xml::events::Event::Empty(e)) => {
                if out.len() > 1000 {
                    return Err(CryptError::Limit("EncryptionInfo has too many elements".into()));
                }
                let local = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                let attrs = e
                    .attributes()
                    .with_checks(false)
                    .flatten()
                    .map(|a| (String::from_utf8_lossy(a.key.local_name().as_ref()).into_owned(), String::from_utf8_lossy(&a.value).into_owned()))
                    .collect();
                out.push(XmlEl { local, attrs });
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(_) => {}
            // lenient as the rest: what was read before a damaged tail counts
            Err(_) => break,
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Standard encryption (§2.3.4.5–§2.3.4.9): Office 2007's, still what Excel writes for some
// files. AES-ECB with a key from SHA-1, 50,000 iterations.

/// Standard encryption's fixed spin count (§2.3.4.7).
const STANDARD_SPIN_COUNT: u32 = 50_000;
/// EncryptionHeader flags (§2.3.1).
const F_CRYPTO_API: u32 = 0x04;
const F_EXTERNAL: u32 = 0x10;
const F_AES: u32 = 0x20;

struct Standard {
    key_bytes: usize,
    salt: Vec<u8>,
    verifier: Vec<u8>,
    verifier_hash: Vec<u8>,
}

/// Versions 2.2, 3.2 and 4.2 are standard encryption (§2.3.4.5).
fn is_standard(info: &[u8]) -> bool {
    matches!(info.get(..4), Some([2..=4, 0, 2, 0]))
}

fn parse_standard(info: &[u8]) -> Result<Standard, CryptError> {
    let u32_at =
        |o: usize| info.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or_else(|| bad("EncryptionInfo is truncated"));
    let flags = u32_at(4)?;
    if flags & F_EXTERNAL != 0 {
        return Err(bad("this file is encrypted by another program's add-in, which can't be opened"));
    }
    if flags & F_CRYPTO_API == 0 || flags & F_AES == 0 {
        return Err(bad("this file uses an encryption other than AES, which can't be opened"));
    }
    let header_size = u32_at(8)? as usize;
    // EncryptionHeader (§2.3.2): Flags, SizeExtra, AlgID, AlgIDHash, KeySize…
    let h = 12;
    let alg = u32_at(h + 8)?;
    let alg_hash = u32_at(h + 12)?;
    let key_bits = match u32_at(h + 16)? {
        0 => 128,
        n => n as usize,
    };
    if !matches!(alg, 0 | 0x660E | 0x660F | 0x6610) || !matches!(alg_hash, 0 | 0x8004) || !matches!(key_bits, 128 | 192 | 256) {
        return Err(bad(format!("unsupported standard encryption (algorithm {alg:#x}, hash {alg_hash:#x}, {key_bits}-bit key)")));
    }
    // EncryptionVerifier (§2.3.3) after the header.
    let v = h.checked_add(header_size).filter(|v| *v <= info.len()).ok_or_else(|| bad("EncryptionInfo is truncated"))?;
    let salt_size = u32_at(v)? as usize;
    if salt_size != 16 {
        return Err(bad("the salt isn't 16 bytes"));
    }
    let slice = |o: usize, n: usize| info.get(o..o + n).map(<[u8]>::to_vec).ok_or_else(|| bad("EncryptionInfo is truncated"));
    let salt = slice(v + 4, 16)?;
    let verifier = slice(v + 20, 16)?;
    if u32_at(v + 36)? != 20 {
        return Err(bad("the verifier hash isn't SHA-1's"));
    }
    let verifier_hash = slice(v + 40, 32)?;
    Ok(Standard { key_bytes: key_bits / 8, salt, verifier, verifier_hash })
}

/// The key (§2.3.4.7): Hn as for agile with SHA-1, then H(Hn + block 0) through CryptDeriveKey's
/// two pads.
fn standard_key(s: &Standard, password: &str) -> Zeroizing<Vec<u8>> {
    let hn = iterate(Hash::Sha1, &s.salt, password, STANDARD_SPIN_COUNT);
    let h = Zeroizing::new(Hash::Sha1.hash(&[&hn, &0u32.to_le_bytes()]));
    let pad = |c: u8| {
        let mut b = Zeroizing::new([c; 64]);
        for (x, y) in b.iter_mut().zip(h.iter()) {
            *x ^= y;
        }
        Zeroizing::new(Hash::Sha1.hash(&[&b[..]]))
    };
    let mut key = Zeroizing::new([pad(0x36).as_slice(), pad(0x5c).as_slice()].concat());
    key.truncate(s.key_bytes);
    key
}

fn decrypt_standard(s: &Standard, password: &str, package: &[u8]) -> Result<Vec<u8>, CryptError> {
    let key = standard_key(s, password);
    // The verifier (§2.3.4.8): a random value, and its SHA-1, encrypted with the key.
    let verifier = Zeroizing::new(ecb_decrypt(&key, &s.verifier)?);
    let hash = Zeroizing::new(ecb_decrypt(&key, &s.verifier_hash)?);
    if !same(&Hash::Sha1.hash(&[&verifier]), hash.get(..20).unwrap_or(&[])) {
        return Err(CryptError::WrongPassword);
    }
    // The package (§2.3.4.4): StreamSize, then the zip, AES-ECB.
    let size = package
        .get(..8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| bad("the encrypted package is truncated"))?;
    let data = package.get(8..).unwrap_or(&[]);
    let size = usize::try_from(size).ok().filter(|s| *s <= data.len()).ok_or_else(|| bad("the encrypted package is truncated"))?;
    let data = data.get(..size.div_ceil(BLOCK).saturating_mul(BLOCK)).ok_or_else(|| bad("the encrypted package is truncated"))?;
    let mut out = ecb_decrypt(&key, data)?;
    out.truncate(size);
    Ok(out)
}

/// AES-ECB decryption: `data` must be whole blocks.
fn ecb_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptError> {
    let aes = Aes::new(key)?;
    let (blocks, rest) = data.as_chunks::<BLOCK>();
    if !rest.is_empty() {
        return Err(bad("encrypted data isn't a whole number of blocks"));
    }
    let mut out = Vec::with_capacity(data.len());
    for b in blocks {
        let mut x = aes::Block::default();
        x.copy_from_slice(b);
        aes.decrypt(&mut x);
        out.extend_from_slice(&x);
    }
    Ok(out)
}
// ---------------------------------------------------------------------------------------------
// Protection passwords (a sheet's, a workbook's structure): not encryption, only a check that the
// password typed is the one set. The file keeps a hash of it.

/// Excel 97–2010's 16-bit password hash ([MS-OFFCRYPTO] §2.3.7.1), the `password="83AF"` of a
/// `sheetProtection`: the password's first 15 characters, one byte each.
pub fn legacy_protection_hash(password: &str) -> u16 {
    let bytes: Vec<u16> = password
        .encode_utf16()
        .take(15)
        .map(|c| match c & 0xFF {
            0 => c >> 8,
            b => b,
        })
        .collect();
    if bytes.is_empty() {
        return 0;
    }
    let rotate = |x: u16| ((x >> 14) & 1) | ((x << 1) & 0x7FFF);
    let mut v: u16 = 0;
    for b in bytes.iter().rev() {
        v = rotate(v) ^ b;
    }
    rotate(v) ^ bytes.len() as u16 ^ 0xCE4B
}

/// A protection password's salted hash as Excel 2013 and later keep it (ECMA-376 Part 1
/// §18.2.29's `algorithmName`, `saltValue`, `spinCount`): H0 = H(salt + password as UTF-16LE),
/// Hn = H(Hn-1 + iterator). `None` for an algorithm this doesn't know.
pub fn protection_hash(algorithm: &str, salt: &[u8], spin_count: u32, password: &str) -> Option<Vec<u8>> {
    let hash = Hash::parse(algorithm)?;
    let pw: Zeroizing<Vec<u8>> = Zeroizing::new(password.encode_utf16().flat_map(u16::to_le_bytes).collect());
    let mut h = hash.hash(&[salt, &pw]);
    for i in 0..spin_count.min(MAX_SPIN_COUNT) {
        h = hash.hash(&[&h, &i.to_le_bytes()]);
    }
    Some(h)
}

/// A new protection hash of `password` as Excel writes it: SHA-512, a random 16-byte salt,
/// 100,000 iterations. (algorithm, salt, hash, spin count), salt and hash in base64.
pub fn new_protection_hash(password: &str) -> Result<(String, String, String, u32), CryptError> {
    let salt = random(SALT)?;
    let hash = protection_hash("SHA-512", &salt, DEFAULT_SPIN_COUNT, password).ok_or_else(|| bad("no SHA-512"))?;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    Ok(("SHA-512".into(), b64(&salt), b64(&hash), DEFAULT_SPIN_COUNT))
}

/// Whether `password` is the one a protection hash was made of (salt and hash in base64).
pub fn protection_password_matches(algorithm: &str, salt: &str, hash: &str, spin_count: u32, password: &str) -> bool {
    let d = |s: &str| base64::engine::general_purpose::STANDARD.decode(s.trim()).ok();
    match (d(salt), d(hash)) {
        (Some(salt), Some(want)) => protection_hash(algorithm, &salt, spin_count, password).is_some_and(|got| same(&got, &want)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands for a zip package: the bytes are only encrypted and decrypted.
    fn zip_package() -> Vec<u8> {
        let mut v = b"PK\x03\x04 Top secret plans".to_vec();
        v.extend((0..10_000u32).map(|i| (i * 31 % 251) as u8));
        v
    }

    #[test]
    fn round_trip_with_a_password() {
        let pkg = zip_package();
        let enc = encrypt_with_spin_count(&pkg, "pässwörd 🔑", 16).unwrap();
        assert!(is_encrypted(&enc));
        assert!(!is_encrypted(&pkg));
        // The compound file carries the data spaces Word expects.
        let comp = cfb::CompoundFile::open(Cursor::new(&enc)).unwrap();
        assert!(comp.is_stream("/\u{6}DataSpaces/TransformInfo/StrongEncryptionTransform/\u{6}Primary"));
        assert_eq!(decrypt(&enc, Some("pässwörd 🔑")).unwrap(), pkg);
        // Without a password, or with the wrong one, it says so instead of opening blank.
        assert_eq!(decrypt(&enc, None), Err(CryptError::PasswordRequired));
        assert_eq!(decrypt(&enc, Some("Pässwörd 🔑")), Err(CryptError::WrongPassword));
        // Excel's built-in password opens without asking.
        let open = encrypt_with_spin_count(&pkg, DEFAULT_PASSWORD, 3).unwrap();
        assert_eq!(decrypt(&open, None).unwrap(), pkg);
        // A package that is a whole number of segments, and an empty one.
        for n in [0usize, SEGMENT, SEGMENT * 2 + 1] {
            let data: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
            let enc = encrypt_with_spin_count(&data, "x", 1).unwrap();
            assert_eq!(decrypt(&enc, Some("x")).unwrap(), data);
        }
        assert!(encrypt(&pkg, "").is_err());
        assert!(encrypt(&pkg, &"x".repeat(MAX_PASSWORD_CHARS + 1)).is_err());
    }

    #[test]
    fn tampered_package_fails_the_integrity_check() {
        let pkg = zip_package();
        let enc = encrypt_with_spin_count(&pkg, "pw", 4).unwrap();
        let mut comp = cfb::CompoundFile::open(Cursor::new(enc)).unwrap();
        let mut data = Vec::new();
        comp.open_stream("/EncryptedPackage").unwrap().read_to_end(&mut data).unwrap();
        let last = data.len() - 1;
        data[last] ^= 1;
        comp.create_stream("/EncryptedPackage").unwrap().write_all(&data).unwrap();
        comp.flush().unwrap();
        let enc = comp.into_inner().into_inner();
        assert!(matches!(decrypt(&enc, Some("pw")), Err(CryptError::Invalid(m)) if m.contains("integrity")));
    }

    /// A compound file with the given EncryptionInfo and EncryptedPackage streams.
    fn cfb_with(info: &[u8], package: &[u8]) -> Vec<u8> {
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        comp.create_stream("/EncryptionInfo").unwrap().write_all(info).unwrap();
        comp.create_stream("/EncryptedPackage").unwrap().write_all(package).unwrap();
        comp.flush().unwrap();
        comp.into_inner().into_inner()
    }

    #[test]
    fn hostile_encryption_info_errors_without_panicking() {
        let good = encrypt_with_spin_count(&zip_package(), "pw", 2).unwrap();
        let mut comp = cfb::CompoundFile::open(Cursor::new(&good)).unwrap();
        let mut info = Vec::new();
        comp.open_stream("/EncryptionInfo").unwrap().read_to_end(&mut info).unwrap();
        let mut package = Vec::new();
        comp.open_stream("/EncryptedPackage").unwrap().read_to_end(&mut package).unwrap();
        let xml = String::from_utf8(info[8..].to_vec()).unwrap();
        // (EncryptionInfo, EncryptedPackage, must fail). Truncations only must not panic: the
        // XML reader is lenient, so cutting the closing tags still reads.
        let mut cases: Vec<(Vec<u8>, Vec<u8>, bool)> = Vec::new();
        for n in (0..info.len()).step_by(7) {
            cases.push((info[..n].to_vec(), package.clone(), n < info.len() / 2));
        }
        for n in [0, 4, 8, 9, 100, package.len() - 1] {
            cases.push((info.clone(), package[..n].to_vec(), true));
        }
        // Unknown versions, absurd numbers, bad base64, a huge StreamSize.
        let with = |from: &str, to: &str| {
            let mut v = info[..8].to_vec();
            v.extend_from_slice(xml.replacen(from, to, 2).as_bytes());
            v
        };
        cases.push(([3u8, 0, 2, 0, 0x24, 0, 0, 0].to_vec(), package.clone(), true));
        cases.push(([3u8, 0, 3, 0, 0x24, 0, 0, 0].to_vec(), package.clone(), true));
        cases.push(([9u8, 0, 9, 0].to_vec(), package.clone(), true));
        cases.push((with("spinCount=\"2\"", "spinCount=\"4294967295\""), package.clone(), true));
        cases.push((with("keyBits=\"256\"", "keyBits=\"8\""), package.clone(), true));
        cases.push((with("blockSize=\"16\"", "blockSize=\"4096\""), package.clone(), true));
        cases.push((with("hashSize=\"64\"", "hashSize=\"0\""), package.clone(), true));
        cases.push((with("saltSize=\"16\"", "saltSize=\"99999999999999999999\""), package.clone(), true));
        cases.push((with("SHA512", "MD5"), package.clone(), true));
        cases.push((with("ChainingModeCBC", "ChainingModeCFB"), package.clone(), true));
        cases.push((with("saltValue=\"", "saltValue=\"!!"), package.clone(), true));
        cases.push((with("encryptedKeyValue=\"", "encryptedKeyValue=\"AAAA"), package.clone(), true));
        // Data integrity is optional; without it a good file still opens.
        cases.push((with("<dataIntegrity", "<nothing"), package.clone(), false));
        let mut huge = package.clone();
        huge[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        cases.push((with("<dataIntegrity", "<nothing"), huge, true));
        for (i, p, must_fail) in cases {
            let file = cfb_with(&i, &p);
            let r = decrypt(&file, Some("pw"));
            assert!(!must_fail || r.is_err());
            assert!(decrypt(&file, None).is_err());
        }
        // A file that only looks like a compound file.
        let mut fake = CFB_MAGIC.to_vec();
        fake.extend_from_slice(&[0u8; 600]);
        assert!(!is_encrypted(&fake));
        assert!(decrypt(&fake, Some("pw")).is_err());
    }

    /// A standard-encrypted file as Office 2007 writes one (§2.3.4.5), for the tests.
    fn standard_file(package: &[u8], password: &str, key_bits: u32) -> Vec<u8> {
        let salt: Vec<u8> = (1..=16).collect();
        let s = Standard { key_bytes: key_bits as usize / 8, salt: salt.clone(), verifier: vec![], verifier_hash: vec![] };
        let key = standard_key(&s, password);
        let aes = Aes::new(&key).unwrap();
        let ecb = |data: &[u8]| -> Vec<u8> {
            let mut out = vec![];
            for b in padded(data).as_chunks::<BLOCK>().0 {
                let mut x = aes::Block::default();
                x.copy_from_slice(b);
                aes.encrypt(&mut x);
                out.extend_from_slice(&x);
            }
            out
        };
        let verifier = [7u8; 16];
        let csp: Vec<u8> = "Microsoft Enhanced RSA and AES Cryptographic Provider\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut header = vec![];
        for v in [F_CRYPTO_API | F_AES, 0, 0x660E + (key_bits - 128) / 64, 0x8004, key_bits, 0x18, 0, 0] {
            header.extend_from_slice(&v.to_le_bytes());
        }
        header.extend_from_slice(&csp);
        let mut info = vec![3, 0, 2, 0];
        info.extend_from_slice(&(F_CRYPTO_API | F_AES).to_le_bytes());
        info.extend_from_slice(&(header.len() as u32).to_le_bytes());
        info.extend_from_slice(&header);
        info.extend_from_slice(&16u32.to_le_bytes());
        info.extend_from_slice(&salt);
        info.extend_from_slice(&ecb(&verifier));
        info.extend_from_slice(&20u32.to_le_bytes());
        info.extend_from_slice(&ecb(&Hash::Sha1.hash(&[&verifier])));
        let mut stream = (package.len() as u64).to_le_bytes().to_vec();
        stream.extend_from_slice(&ecb(package));
        cfb_with(&info, &stream)
    }

    #[test]
    fn standard_encryption_opens() {
        let pkg = zip_package();
        for bits in [128, 192, 256] {
            let file = standard_file(&pkg, "tika", bits);
            assert!(is_encrypted(&file));
            assert_eq!(decrypt(&file, Some("tika")).unwrap(), pkg, "{bits}");
            assert_eq!(decrypt(&file, Some("Tika")), Err(CryptError::WrongPassword));
            assert_eq!(decrypt(&file, None), Err(CryptError::PasswordRequired));
        }
        // Excel's built-in password: no prompt.
        assert_eq!(decrypt(&standard_file(&pkg, DEFAULT_PASSWORD, 128), None).unwrap(), pkg);
        // Damaged: errors, no panic.
        let good = standard_file(&pkg, "pw", 128);
        let mut comp = cfb::CompoundFile::open(Cursor::new(&good)).unwrap();
        let mut info = Vec::new();
        comp.open_stream("/EncryptionInfo").unwrap().read_to_end(&mut info).unwrap();
        let mut package = Vec::new();
        comp.open_stream("/EncryptedPackage").unwrap().read_to_end(&mut package).unwrap();
        for n in (0..info.len()).step_by(5) {
            assert!(decrypt(&cfb_with(&info[..n], &package), Some("pw")).is_err());
        }
        for n in [0, 7, 8, 9, 100] {
            assert!(decrypt(&cfb_with(&info, &package[..n]), Some("pw")).is_err());
        }
    }

    /// Files from elsewhere with their passwords, when `OFFICE_CRYPT_FILES` names a folder holding
    /// them (Apache POI's test files): `name=password` pairs, comma-separated, in
    /// `OFFICE_CRYPT_PASSWORDS`; a file without one must open with none.
    #[test]
    fn real_files_open() {
        let (Ok(dir), Ok(list)) = (std::env::var("OFFICE_CRYPT_FILES"), std::env::var("OFFICE_CRYPT_PASSWORDS")) else { return };
        for item in list.split(',') {
            let (name, pw) = item.split_once('=').unwrap_or((item, ""));
            let bytes = std::fs::read(std::path::Path::new(&dir).join(name)).unwrap();
            let zip = decrypt(&bytes, (!pw.is_empty()).then_some(pw)).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(zip.starts_with(b"PK"), "{name}");
        }
    }

    #[test]
    fn protection_hashes_are_excels() {
        // Excel's own values: "password" is 83AF, and Apache POI's
        // workbookProtection-workbook_password_user_range-2010.xlsx has "test" as CBEB.
        assert_eq!(legacy_protection_hash("password"), 0x83AF);
        assert_eq!(legacy_protection_hash("test"), 0xCBEB);
        assert_eq!(legacy_protection_hash(""), 0);
        // POI's workbookProtection-sheet_password-2013.xlsx, password "pwd".
        let (salt, hash) = ("R040EdN/Ec7il6MJ8JrRLQ==", "5MANCkOK6IY02H1LhiJ+ucR5ZHvoV7BwbINSx52iIhe4Xfg986k2l32ONsYpt8JPiy8U8kqPRKXIr7G8hfMWOw==");
        assert!(protection_password_matches("SHA-512", salt, hash, 100_000, "pwd"));
        assert!(!protection_password_matches("SHA-512", salt, hash, 100_000, "Pwd"));
        assert!(!protection_password_matches("MD5", salt, hash, 100_000, "pwd"));
        assert!(!protection_password_matches("SHA-512", "!!", hash, 100_000, "pwd"));
        let (alg, salt, hash, spins) = new_protection_hash("geheim").unwrap();
        assert!(protection_password_matches(&alg, &salt, &hash, spins, "geheim"));
    }
}
