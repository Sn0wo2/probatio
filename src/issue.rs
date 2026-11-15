use crate::Error;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, iana};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

#[derive(Debug)]
pub struct Issuer {
    sk: SigningKey,
}

impl Issuer {
    pub fn new(seed: &[u8; 32]) -> Self {
        Self {
            sk: SigningKey::from_bytes(seed),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }

    pub fn issue_claims<T: Serialize>(&self, claims: &T) -> Result<Vec<u8>, Error> {
        self.issue_claims_with(claims, &[], &[])
    }

    pub fn issue_claims_with<T: Serialize>(
        &self,
        claims: &T,
        kid: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut payload = Vec::new();
        ciborium::ser::into_writer(claims, &mut payload)
            .map_err(|e| Error::Claims(e.to_string()))?;
        self.issue_with(payload, kid, aad)
    }

    pub fn issue(&self, payload: Vec<u8>) -> Result<Vec<u8>, Error> {
        self.issue_with(payload, &[], &[])
    }

    pub fn issue_with(&self, payload: Vec<u8>, kid: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let mut header = HeaderBuilder::new().algorithm(iana::Algorithm::EdDSA);
        if !kid.is_empty() {
            header = header.key_id(kid.to_vec());
        }

        CoseSign1Builder::new()
            .protected(header.build())
            .payload(payload)
            .create_signature(aad, |tbs| self.sk.sign(tbs).to_bytes().to_vec())
            .build()
            .to_vec()
            .map_err(Into::into)
    }
}
