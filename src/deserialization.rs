use base64::prelude::*;
use duration_string::DurationString;
use sphinx_packet::SURB;
use std::{fmt::Display, time::Duration};

use serde::{
    de::{self},
    Deserialize, Deserializer, Serializer,
};

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

pub fn u8_32_from_base64<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    T: From<[u8; 32]>,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        Err(de::Error::custom(CryptoDeserializationError::Empty))
    } else {
        let b = BASE64_STANDARD
            .decode(s)
            .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
        let a: [u8; 32] = b
            .try_into()
            .map_err(|_| de::Error::custom(CryptoDeserializationError::BadLength))?;
        Ok(T::from(a))
    }
}

pub fn u8_32_from_base64_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: From<[u8; 32]>,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        Ok(None)
    } else {
        let b = BASE64_STANDARD
            .decode(s)
            .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
        let a: [u8; 32] = b
            .try_into()
            .map_err(|_| de::Error::custom(CryptoDeserializationError::BadLength))?;
        Ok(Some(T::from(a)))
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

pub fn surb_as_base64_option<S>(key: &Option<SURB>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match key {
        Some(key) => serializer.serialize_str(&BASE64_STANDARD.encode(key.to_bytes())),
        None => serializer.serialize_none(),
    }
}

pub fn surb_from_base64_option<'de, D>(deserializer: D) -> Result<Option<SURB>, D::Error>
where
    D: Deserializer<'de>,
{
    let string = String::deserialize(deserializer)?;
    if string.is_empty() {
        Ok(None)
    } else {
        let bytes = BASE64_STANDARD
            .decode(string)
            .map_err(|_| de::Error::custom(CryptoDeserializationError::InvalidBase64))?;
        let surb = SURB::from_bytes(&bytes).map_err(de::Error::custom)?;
        Ok(Some(surb))
    }
}

pub fn duration_from_durationstring_option<'de, D>(
    deserializer: D,
) -> Result<Option<Duration>, D::Error>
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

pub fn as_durationstring_option<S>(key: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match key {
        Some(d) => {
            let ds: String = DurationString::from(*d).into();
            serializer.serialize_str(&ds)
        }
        None => serializer.serialize_none(),
    }
}
