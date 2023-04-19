use std::{convert::TryFrom, fmt::Debug};

use josekit::{
    jwe::{JweDecrypter, JweEncrypter, ECDH_ES, RSA_OAEP},
    jws::{JwsSigner, JwsVerifier, ES256, RS256},
};
use serde::{Deserialize, Serialize};

use crate::error::Error;

// Configuration management
//
#[derive(Serialize, Deserialize)]
pub struct InnerKeyConfig {
    key: String,
}

impl Debug for InnerKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InnerKeyConfig").finish()
    }
}

/// Parsable configuration describing an encryption key.
/// This can be cast (using try_from) into the JweDecryptor en JweEncryptor
/// types needed by the jwe functions.
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum EncryptionKeyConfig {
    RSA(InnerKeyConfig),
    EC(InnerKeyConfig),
}

impl TryFrom<EncryptionKeyConfig> for Box<dyn JweDecrypter> {
    type Error = Error;

    fn try_from(value: EncryptionKeyConfig) -> Result<Box<dyn JweDecrypter>, Error> {
        match value {
            EncryptionKeyConfig::RSA(key) => Ok(Box::new(RSA_OAEP.decrypter_from_pem(key.key)?)),
            EncryptionKeyConfig::EC(key) => Ok(Box::new(ECDH_ES.decrypter_from_pem(key.key)?)),
        }
    }
}

impl TryFrom<EncryptionKeyConfig> for Box<dyn JweEncrypter> {
    type Error = Error;

    fn try_from(value: EncryptionKeyConfig) -> Result<Box<dyn JweEncrypter>, Error> {
        match value {
            EncryptionKeyConfig::RSA(key) => Ok(Box::new(RSA_OAEP.encrypter_from_pem(key.key)?)),
            EncryptionKeyConfig::EC(key) => Ok(Box::new(ECDH_ES.encrypter_from_pem(key.key)?)),
        }
    }
}

/// Parsable configuration describing a signature key.
/// This can be cast (using try_from) into the JwsVerifier and JwsSigner types
/// needed by the jwe functions.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum SignKeyConfig {
    RSA(InnerKeyConfig),
    EC(InnerKeyConfig),
}

impl TryFrom<SignKeyConfig> for Box<dyn JwsVerifier> {
    type Error = Error;

    fn try_from(value: SignKeyConfig) -> Result<Box<dyn JwsVerifier>, Error> {
        match value {
            SignKeyConfig::RSA(key) => Ok(Box::new(RS256.verifier_from_pem(key.key)?)),
            SignKeyConfig::EC(key) => Ok(Box::new(ES256.verifier_from_pem(key.key)?)),
        }
    }
}

impl TryFrom<SignKeyConfig> for Box<dyn JwsSigner> {
    type Error = Error;

    fn try_from(value: SignKeyConfig) -> Result<Box<dyn JwsSigner>, Error> {
        match value {
            SignKeyConfig::RSA(key) => Ok(Box::new(RS256.signer_from_pem(key.key)?)),
            SignKeyConfig::EC(key) => Ok(Box::new(ES256.signer_from_pem(key.key)?)),
        }
    }
}
