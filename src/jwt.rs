use std::collections::HashMap;

use josekit::{
    jwe::{JweDecrypter, JweEncrypter, JweHeader},
    jws::{JwsHeader, JwsSigner, JwsVerifier},
    jwt::{self, JwtPayload},
};

use id_contact_proto::{AuthResult, AuthStatus};

use crate::error::Error;

//
// Jwe manipulation
//

/// Sign and encrypt a given set of attributes.
pub fn sign_and_encrypt_auth_result(
    auth_result: &AuthResult,
    signer: &dyn JwsSigner,
    encrypter: &dyn JweEncrypter,
) -> Result<String, Error> {
    let mut sig_header = JwsHeader::new();
    sig_header.set_token_type("JWT");
    let mut sig_payload = JwtPayload::new();
    sig_payload.set_subject("id-contact-attributes");
    sig_payload.set_claim("status", Some(serde_json::to_value(&auth_result.status)?))?;
    if let Some(attributes) = &auth_result.attributes {
        sig_payload.set_claim("attributes", Some(serde_json::to_value(attributes)?))?;
    }
    if let Some(session_url) = &auth_result.session_url {
        sig_payload.set_claim("session_url", Some(serde_json::to_value(session_url)?))?;
    }
    sig_payload.set_issued_at(&std::time::SystemTime::now());
    sig_payload.set_expires_at(&(std::time::SystemTime::now() + std::time::Duration::from_secs(5*60)));

    let jws = jwt::encode_with_signer(&sig_payload, &sig_header, signer)?;

    let mut enc_header = JweHeader::new();
    enc_header.set_token_type("JWT");
    enc_header.set_content_type("JWT");
    enc_header.set_content_encryption("A128CBC-HS256");
    let mut enc_payload = JwtPayload::new();
    enc_payload.set_claim("njwt", Some(serde_json::to_value(jws)?))?;

    Ok(jwt::encode_with_encrypter(
        &enc_payload,
        &enc_header,
        encrypter,
    )?)
}

/// Decrypt and verify a given jwe to extract the contained attributes.
pub fn decrypt_and_verify_auth_result(
    jwe: &str,
    validator: &dyn JwsVerifier,
    decrypter: &dyn JweDecrypter,
) -> Result<AuthResult, Error> {
    let decoded_jwe = jwt::decode_with_decrypter(jwe, decrypter)?.0;
    let jws = decoded_jwe
        .claim("njwt")
        .ok_or(Error::InvalidStructure)?
        .as_str()
        .ok_or(Error::InvalidStructure)?;
    let decoded_jws = jwt::decode_with_verifier(jws, validator)?.0;
    let status = decoded_jws
        .claim("status")
        .ok_or(Error::InvalidStructure)?;
    let status = serde_json::from_value::<AuthStatus>(status.clone())?;
    let attributes = decoded_jws
        .claim("attributes");
    let attributes = match attributes {
        Some(raw_attributes) => Some(serde_json::from_value::<HashMap<String, String>>(raw_attributes.clone())?),
        None => None,
    };
    let session_url = decoded_jws
        .claim("session_url");
    let session_url = match session_url {
        Some(session_url) => Some(serde_json::from_value::<String>(session_url.clone())?),
        None => None,
    };

    Ok(AuthResult {
        status,
        attributes,
        session_url,
    })
}
