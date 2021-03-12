//! id-contact-jwe provides basic utilities for manipulating and creating ID-Contact jwes from rust.

mod config;
mod error;
mod jwt;

pub use config::{EncryptionKeyConfig, SignKeyConfig};
pub use error::Error;
pub use jwt::{decrypt_and_verify_auth_result, sign_and_encrypt_auth_result};

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::convert::TryFrom;

    use id_contact_proto::{AuthResult, AuthStatus};
    use josekit::{
        jwe::{JweDecrypter, JweEncrypter},
        jws::{JwsSigner, JwsVerifier},
    };

    const RSA_PUBKEY: &str = r"
    type: RSA
    key: |
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5/wRrT2T4GGvuQYcWjLr
        /lFe51sTV2FLd3GAaMiHN8Q/VT/XEhP/kZ6042l1Bj2VpZ2yMxv294JKwBCINc34
        8VLYd+DfkMnJ4yX9LZHK2Wke6tCWBB9mYgGjMwCNdXczbl96x1/HevaTorvk91rz
        Cvzw6vV08jtprAyN5aYMU4I0/cVJwi03bh/skraAB110mQSqi1QU/2z6Hkuf7+/x
        /bACxviWCyPCd/wkXNpFhTcRlfFeyKcy0pwFx1OLCDJ1qY7oU+z1wcypeOHeiUSx
        riSHlWaT24ke+J78GGVmnCZdu/MRuun5hvgaiWxnhIBmExJY6vRuMlwkbRqOft5Q
        TQIDAQAB
        -----END PUBLIC KEY-----
    ";

    const RSA_PRIVKEY: &str = r"
    type: RSA
    key: |
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDn/BGtPZPgYa+5
        BhxaMuv+UV7nWxNXYUt3cYBoyIc3xD9VP9cSE/+RnrTjaXUGPZWlnbIzG/b3gkrA
        EIg1zfjxUth34N+QycnjJf0tkcrZaR7q0JYEH2ZiAaMzAI11dzNuX3rHX8d69pOi
        u+T3WvMK/PDq9XTyO2msDI3lpgxTgjT9xUnCLTduH+yStoAHXXSZBKqLVBT/bPoe
        S5/v7/H9sALG+JYLI8J3/CRc2kWFNxGV8V7IpzLSnAXHU4sIMnWpjuhT7PXBzKl4
        4d6JRLGuJIeVZpPbiR74nvwYZWacJl278xG66fmG+BqJbGeEgGYTEljq9G4yXCRt
        Go5+3lBNAgMBAAECggEARY9EsaCMLbS83wrhB37LWneFsHOTqhjHaypCaajvOp6C
        qwo4b/hFIqHm9WWSrGtc6ssNOtwAwphz14Fdhlybb6j6tX9dKeoHui+S6c4Ud/pY
        ReqDgPr1VR/OkqVwxS8X4dmJVCz5AHrdK+eRMUY5KCtOBfXRuixsdCVTiu+uNH99
        QC3kID1mmOF3B0chOK4WPN4cCsQpfOvoJfPBcJOtyxUSLlQdJH+04s3gVA24nCJj
        66+AnVkjgkyQ3q0Jugh1vo0ikrUW8uSLmg40sT5eYDN9jP6r5Gc8yDqsmYNVbLhU
        pY8XR4gtzbtAXK8R2ISKNhOSuTv4SWFXVZiDIBkuIQKBgQD3qnZYyhGzAiSM7T/R
        WS9KrQlzpRV5qSnEp2sPG/YF+SGAdgOaWOEUa3vbkCuLCTkoJhdTp67BZvv/657Q
        2eK2khsYRs02Oq+4rYvdcAv/wS2vkMbg6CUp1w2/pwBvwFTXegr00k6IabXNcXBy
        kAjMsZqVDSdQByrf80AlFyEsOQKBgQDvyoUDhLReeDNkbkPHL/EHD69Hgsc77Hm6
        MEiLdNljTJLRUl+DuD3yKX1xVBaCLp9fMJ/mCrxtkldhW+i6JBHRQ7vdf11zNsRf
        2Cud3Q97RMHTacCHhEQDGnYkOQNTRhk8L31N0XBKfUu0phSmVyTnu2lLWmYJ8hyO
        yOEB19JstQKBgQC3oVw+WRTmdSBEnWREBKxb4hCv/ib+Hb8qYDew7DpuE1oTtWzW
        dC/uxAMBuNOQMzZ93kBNdnbMT19pUXpfwC2o0IvmZBijrL+9Xm/lr7410zXchqvu
        9jEX5Kv8/gYE1cYSPhsBiy1PV5HE0edeCg18N/M1sJsFa0sO4X0eAxhFgQKBgQC7
        iQDkUooaBBn1ZsM9agIwSpUD8YTOGdDNy+tAnf9SSNXePXUT+CkCVm6UDnaYE8xy
        zv2PFUBu1W/fZdkqkwEYT8gCoBS/AcstRkw+Z2AvQQPxyxhXJBto7e4NwEUYgI9F
        4cI29SDEMR/fRbCKs0basVjVJPr+tkqdZP+MyHT6rQKBgQCT1YjY4F45Qn0Vl+sZ
        HqwVHvPMwVsexcRTdC0evaX/09s0xscSACvFJh5Dm9gnuMHElBcpZFATIvFcbV5Y
        MbJ/NNQiD63NEcL9VXwT96sMx2tnduOq4sYzu84kwPQ4ohxmPt/7xHU3L8SGqoec
        Bs6neR/sZuHzNm8y/xtxj2ZAEw==
        -----END PRIVATE KEY-----
    ";

    const EC_PUBKEY: &str = r"
    type: EC
    key: |
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZLquEijJ7cP7K9qIHG7EvCTph53N
        4nz61OgeuZWdvM7LyBVXuW53nY+b6NJmophgcZHqzSiLbk+jPvIGvVUxzQ==
        -----END PUBLIC KEY-----
    ";

    const EC_PRIVKEY: &str = r"
    type: EC
    key: |
        -----BEGIN PRIVATE KEY-----
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJdHGkAfKUVshsNPQ
        5UA9sNCf74eALrLrtBQE1nDFlv+hRANCAARkuq4SKMntw/sr2ogcbsS8JOmHnc3i
        fPrU6B65lZ28zsvIFVe5bnedj5vo0maimGBxkerNKItuT6M+8ga9VTHN
        -----END PRIVATE KEY-----
    ";

    #[test]
    fn roundtrip_test_rsa() {
        let enc_config: EncryptionKeyConfig = serde_yaml::from_str(RSA_PUBKEY).unwrap();
        let dec_config: EncryptionKeyConfig = serde_yaml::from_str(RSA_PRIVKEY).unwrap();

        let decrypter = Box::<dyn JweDecrypter>::try_from(dec_config).unwrap();
        let encrypter = Box::<dyn JweEncrypter>::try_from(enc_config).unwrap();

        let sig_config: SignKeyConfig = serde_yaml::from_str(RSA_PRIVKEY).unwrap();
        let ver_config: SignKeyConfig = serde_yaml::from_str(RSA_PUBKEY).unwrap();

        let signer = Box::<dyn JwsSigner>::try_from(sig_config).unwrap();
        let verifier = Box::<dyn JwsVerifier>::try_from(ver_config).unwrap();

        let mut test_attributes: HashMap<String, String> = HashMap::new();

        test_attributes.insert("A".to_string(), "B".to_string());
        test_attributes.insert("C".to_string(), "D".to_string());

        // failed
        let in_result = AuthResult {
            status: AuthStatus::Failed,
            attributes: None,
            session_url: None,
        };
        let jwe =
            sign_and_encrypt_auth_result(&in_result, signer.as_ref(), encrypter.as_ref())
                .unwrap();
        let out_result =
            decrypt_and_verify_auth_result(&jwe, verifier.as_ref(), decrypter.as_ref()).unwrap();
        assert_eq!(in_result, out_result);

        // succes+attributes
        let in_result = AuthResult {
            status: AuthStatus::Succes,
            attributes: Some(test_attributes.clone()),
            session_url: None,
        };
        let jwe =
            sign_and_encrypt_auth_result(&in_result, signer.as_ref(), encrypter.as_ref())
                .unwrap();
        let out_result =
            decrypt_and_verify_auth_result(&jwe, verifier.as_ref(), decrypter.as_ref()).unwrap();
        assert_eq!(in_result, out_result);

        // succes+attributes+session_url
        let in_result = AuthResult {
            status: AuthStatus::Succes,
            attributes: Some(test_attributes.clone()),
            session_url: Some("https://example.com".to_string()),
        };
        let jwe =
            sign_and_encrypt_auth_result(&in_result, signer.as_ref(), encrypter.as_ref())
                .unwrap();
        let out_result =
            decrypt_and_verify_auth_result(&jwe, verifier.as_ref(), decrypter.as_ref()).unwrap();
        assert_eq!(in_result, out_result);
    }

    #[test]
    fn roundtrip_test_ec() {
        let enc_config: EncryptionKeyConfig = serde_yaml::from_str(EC_PUBKEY).unwrap();
        let dec_config: EncryptionKeyConfig = serde_yaml::from_str(EC_PRIVKEY).unwrap();

        let decrypter = Box::<dyn JweDecrypter>::try_from(dec_config).unwrap();
        let encrypter = Box::<dyn JweEncrypter>::try_from(enc_config).unwrap();

        let sig_config: SignKeyConfig = serde_yaml::from_str(EC_PRIVKEY).unwrap();
        let ver_config: SignKeyConfig = serde_yaml::from_str(EC_PUBKEY).unwrap();

        let signer = Box::<dyn JwsSigner>::try_from(sig_config).unwrap();
        let verifier = Box::<dyn JwsVerifier>::try_from(ver_config).unwrap();

        let mut test_attributes: HashMap<String, String> = HashMap::new();

        test_attributes.insert("A".to_string(), "B".to_string());
        test_attributes.insert("C".to_string(), "D".to_string());

        // failed
        let in_result = AuthResult {
            status: AuthStatus::Failed,
            attributes: None,
            session_url: None,
        };
        let jwe =
            sign_and_encrypt_auth_result(&in_result, signer.as_ref(), encrypter.as_ref())
                .unwrap();
        let out_result =
            decrypt_and_verify_auth_result(&jwe, verifier.as_ref(), decrypter.as_ref()).unwrap();
        assert_eq!(in_result, out_result);

        // succes+attributes
        let in_result = AuthResult {
            status: AuthStatus::Succes,
            attributes: Some(test_attributes.clone()),
            session_url: None,
        };
        let jwe =
            sign_and_encrypt_auth_result(&in_result, signer.as_ref(), encrypter.as_ref())
                .unwrap();
        let out_result =
            decrypt_and_verify_auth_result(&jwe, verifier.as_ref(), decrypter.as_ref()).unwrap();
        assert_eq!(in_result, out_result);

        // succes+attributes+session_url
        let in_result = AuthResult {
            status: AuthStatus::Succes,
            attributes: Some(test_attributes.clone()),
            session_url: Some("https://example.com".to_string()),
        };
        let jwe =
            sign_and_encrypt_auth_result(&in_result, signer.as_ref(), encrypter.as_ref())
                .unwrap();
        let out_result =
            decrypt_and_verify_auth_result(&jwe, verifier.as_ref(), decrypter.as_ref()).unwrap();
        assert_eq!(in_result, out_result);
    }
}
