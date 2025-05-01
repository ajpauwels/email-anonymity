use base64::prelude::*;
use duration_string::DurationString;
use std::{fmt::Display, time::Duration};

use serde::{de, Deserialize, Deserializer, Serializer};
use sodiumoxide::crypto::box_::{Nonce, PublicKey as PublicKeyNaCl, SecretKey as SecretKeyNaCl};
use x25519_dalek::{PublicKey as PublicKeyDalek, StaticSecret as StaticSecretDalek};

pub fn empty_string_is_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        Ok(None)
    } else {
        Ok(Some(s))
    }
}

#[derive(Debug)]
pub enum CryptoDeserializationError {
    Message(String),
    Empty,
    InvalidBase64,
    BadLength,
}

impl de::Error for CryptoDeserializationError {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        CryptoDeserializationError::Message(msg.to_string())
    }
}

impl std::error::Error for CryptoDeserializationError {}

impl Display for CryptoDeserializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoDeserializationError::Message(msg) => f.write_str(msg),
            CryptoDeserializationError::Empty => f.write_str("Value is an empty string"),
            CryptoDeserializationError::InvalidBase64 => f.write_str("Value is not valid base64"),
            CryptoDeserializationError::BadLength => f.write_str("Value was the wrong length"),
        }
    }
}

#[derive(Debug)]
pub enum DurationDeserializationError {
    Message(String),
    InvalidString,
}

impl de::Error for DurationDeserializationError {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        DurationDeserializationError::Message(msg.to_string())
    }
}

impl std::error::Error for DurationDeserializationError {}

impl Display for DurationDeserializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DurationDeserializationError::Message(msg) => f.write_str(msg),
            DurationDeserializationError::InvalidString => {
                f.write_str("String is not a valid duration")
            }
        }
    }
}

pub fn string_is_ecc_public_key<'de, D>(deserializer: D) -> Result<PublicKeyNaCl, D::Error>
where
    D: Deserializer<'de>,
{
    let key_string = String::deserialize(deserializer)?;
    if key_string.is_empty() {
        Err(de::Error::custom(CryptoDeserializationError::Empty))
    } else {
        let key_bytes = BASE64_STANDARD
            .decode(key_string)
            .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
        let pk = PublicKeyNaCl::from_slice(key_bytes.as_ref())
            .ok_or(de::Error::custom(CryptoDeserializationError::BadLength))?;
        Ok(pk)
    }
}

pub fn string_is_ecc_public_key_option<'de, D>(
    deserializer: D,
) -> Result<Option<PublicKeyNaCl>, D::Error>
where
    D: Deserializer<'de>,
{
    let key_string = String::deserialize(deserializer)?;
    if key_string.is_empty() {
        Ok(None)
    } else {
        let key_bytes = BASE64_STANDARD
            .decode(key_string)
            .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
        let pk = PublicKeyNaCl::from_slice(key_bytes.as_ref())
            .ok_or(de::Error::custom(CryptoDeserializationError::BadLength))?;
        Ok(Some(pk))
    }
}

pub fn string_is_ecc_public_key_dalek<'de, D>(deserializer: D) -> Result<PublicKeyDalek, D::Error>
where
    D: Deserializer<'de>,
{
    let key_string = String::deserialize(deserializer)?;
    if key_string.is_empty() {
        Err(de::Error::custom(CryptoDeserializationError::Empty))
    } else {
        let key_bytes = BASE64_STANDARD
            .decode(key_string)
            .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
        let key_bytes_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| de::Error::custom(CryptoDeserializationError::BadLength))?;
        let pk = PublicKeyDalek::from(key_bytes_array);
        Ok(pk)
    }
}

// pub fn string_is_ecc_public_key_dalek_option<'de, D>(
//     deserializer: D,
// ) -> Result<Option<PublicKeyDalek>, D::Error>
// where
//     D: Deserializer<'de>,
// {
//     let key_string = String::deserialize(deserializer)?;
//     if key_string.is_empty() {
//         Ok(None)
//     } else {
//         let key_bytes = BASE64_STANDARD
//             .decode(key_string)
//             .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
//         let key_bytes_array: [u8; 32] = key_bytes
//             .try_into()
//             .map_err(|_| de::Error::custom(CryptoDeserializationError::BadLength))?;
//         let pk = PublicKeyDalek::from(key_bytes_array);
//         Ok(Some(pk))
//     }
// }

pub fn string_is_ecc_secret_key<'de, D>(deserializer: D) -> Result<SecretKeyNaCl, D::Error>
where
    D: Deserializer<'de>,
{
    let key_string = String::deserialize(deserializer)?;
    if key_string.is_empty() {
        Err(de::Error::custom(CryptoDeserializationError::Empty))
    } else {
        let key_bytes = BASE64_STANDARD
            .decode(key_string)
            .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
        let sk = SecretKeyNaCl::from_slice(key_bytes.as_ref())
            .ok_or(de::Error::custom(CryptoDeserializationError::BadLength))?;
        Ok(sk)
    }
}

// pub fn string_is_ecc_secret_key_option<'de, D>(
//     deserializer: D,
// ) -> Result<Option<SecretKeyNaCl>, D::Error>
// where
//     D: Deserializer<'de>,
// {
//     let key_string = String::deserialize(deserializer)?;
//     if key_string.is_empty() {
//         Ok(None)
//     } else {
//         let key_bytes = BASE64_STANDARD
//             .decode(key_string)
//             .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
//         let sk = SecretKeyNaCl::from_slice(key_bytes.as_ref())
//             .ok_or(de::Error::custom(CryptoDeserializationError::BadLength))?;
//         Ok(Some(sk))
//     }
// }

pub fn string_is_ecc_secret_key_dalek<'de, D>(
    deserializer: D,
) -> Result<StaticSecretDalek, D::Error>
where
    D: Deserializer<'de>,
{
    let key_string = String::deserialize(deserializer)?;
    if key_string.is_empty() {
        Err(de::Error::custom(CryptoDeserializationError::Empty))
    } else {
        let key_bytes = BASE64_STANDARD
            .decode(key_string)
            .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
        let key_bytes_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| de::Error::custom(CryptoDeserializationError::BadLength))?;
        let sk = StaticSecretDalek::from(key_bytes_array);
        Ok(sk)
    }
}

// pub fn string_is_ecc_secret_key_dalek_option<'de, D>(
//     deserializer: D,
// ) -> Result<Option<StaticSecretDalek>, D::Error>
// where
//     D: Deserializer<'de>,
// {
//     let key_string = String::deserialize(deserializer)?;
//     if key_string.is_empty() {
//         Ok(None)
//     } else {
//         let key_bytes = BASE64_STANDARD
//             .decode(key_string)
//             .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
//         let key_bytes_array: [u8; 32] = key_bytes
//             .try_into()
//             .map_err(|_| de::Error::custom(CryptoDeserializationError::BadLength))?;
//         let sk = StaticSecretDalek::from(key_bytes_array);
//         Ok(Some(sk))
//     }
// }

pub fn string_is_nonce<'de, D>(deserializer: D) -> Result<Nonce, D::Error>
where
    D: Deserializer<'de>,
{
    let key_string = String::deserialize(deserializer)?;
    if key_string.is_empty() {
        Err(de::Error::custom(CryptoDeserializationError::Empty))
    } else {
        let nonce_bytes = BASE64_STANDARD
            .decode(key_string)
            .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
        let sk = Nonce::from_slice(nonce_bytes.as_ref())
            .ok_or(de::Error::custom(CryptoDeserializationError::BadLength))?;
        Ok(sk)
    }
}

pub fn string_is_nonce_option<'de, D>(deserializer: D) -> Result<Option<Nonce>, D::Error>
where
    D: Deserializer<'de>,
{
    let key_string = String::deserialize(deserializer)?;
    if key_string.is_empty() {
        Ok(None)
    } else {
        let nonce_bytes = BASE64_STANDARD
            .decode(key_string)
            .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
        let sk = Nonce::from_slice(nonce_bytes.as_ref())
            .ok_or(de::Error::custom(CryptoDeserializationError::BadLength))?;
        Ok(Some(sk))
    }
}

pub fn as_base64<T, S>(key: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&BASE64_STANDARD.encode(key.as_ref()))
}

pub fn as_base64_option<T, S>(key: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    match key {
        Some(key) => serializer.serialize_str(&BASE64_STANDARD.encode(key.as_ref())),
        None => serializer.serialize_none(),
    }
}

pub fn string_is_duration_option<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let duration_string = String::deserialize(deserializer)?;
    if duration_string.is_empty() {
        Ok(None)
    } else {
        let duration = DurationString::try_from(duration_string)
            .map_err(|_| de::Error::custom(DurationDeserializationError::InvalidString))?;
        Ok(Some(duration.into()))
    }
}
