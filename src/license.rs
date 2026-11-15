use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(clippy::exhaustive_enums)]
pub enum HwidCheck {
    Unbound,
    Match,
    Mismatch,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[expect(clippy::exhaustive_structs)]
pub struct License {
    pub lic: Option<String>,
    pub sku: Option<String>,
    pub features: BTreeSet<String>,
    pub iat: Option<u64>,
    pub nbf: Option<u64>,
    pub exp: Option<u64>,
    #[serde(with = "serde_bytes")]
    pub hwid: Option<Vec<u8>>,
    pub tag: Option<String>,
}

impl License {
    pub fn is_active_at(&self, unix_secs: u64) -> bool {
        self.nbf.is_none_or(|nbf| unix_secs >= nbf) && self.exp.is_none_or(|exp| unix_secs < exp)
    }

    pub fn hwid_check(&self, local_fingerprint: &[u8]) -> HwidCheck {
        match &self.hwid {
            None => HwidCheck::Unbound,
            Some(bound) if bound.ct_eq(local_fingerprint).into() => HwidCheck::Match,
            Some(_) => HwidCheck::Mismatch,
        }
    }
}
