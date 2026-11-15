#![expect(clippy::pub_use)]

mod license;

#[cfg(feature = "issue")]
mod issue;

pub use license::{HwidCheck, License};

#[cfg(feature = "issue")]
pub use issue::Issuer;

use coset::{
    Algorithm, CborSerializable, CoseSign1, ProtectedHeader, TaggedCborSerializable, iana,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeOwned;

#[derive(Debug, thiserror::Error)]
#[expect(clippy::exhaustive_enums)]
pub enum Error {
    #[error("invalid public key")]
    InvalidKey,
    #[error("malformed token")]
    Malformed(#[from] coset::CoseError),
    #[error("unsupported signature algorithm (expected EdDSA / COSE -8)")]
    UnsupportedAlg,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("token carries no payload")]
    NoPayload,
    #[error("malformed claims: {0}")]
    Claims(String),
}

#[derive(Debug)]
#[expect(clippy::exhaustive_structs)]
pub struct Verified {
    pub payload: Vec<u8>,
    pub protected: ProtectedHeader,
}

impl Verified {
    pub fn claims<T: DeserializeOwned>(&self) -> Result<T, Error> {
        ciborium::de::from_reader(&self.payload[..]).map_err(|e| Error::Claims(e.to_string()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Verifier {
    vk: VerifyingKey,
}

impl Verifier {
    pub fn new(public_key: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self {
            vk: VerifyingKey::from_bytes(public_key).map_err(|_| Error::InvalidKey)?,
        })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.vk.to_bytes()
    }

    pub fn verify(&self, token: impl AsRef<[u8]>) -> Result<Verified, Error> {
        self.verify_with_aad(token, &[])
    }

    pub fn verify_with_aad(&self, token: impl AsRef<[u8]>, aad: &[u8]) -> Result<Verified, Error> {
        let sign1 = CoseSign1::from_tagged_slice(token.as_ref())
            .or_else(|_| CoseSign1::from_slice(token.as_ref()))?;

        if sign1.protected.header.alg != Some(Algorithm::Assigned(iana::Algorithm::EdDSA)) {
            return Err(Error::UnsupportedAlg);
        }

        sign1.verify_signature(aad, |sig, tbs| {
            self.vk
                .verify_strict(
                    tbs,
                    &Signature::from_slice(sig).map_err(|_| Error::InvalidSignature)?,
                )
                .map_err(|_| Error::InvalidSignature)
        })?;

        Ok(Verified {
            payload: sign1.payload.ok_or(Error::NoPayload)?,
            protected: sign1.protected,
        })
    }
}
