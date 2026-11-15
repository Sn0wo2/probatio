use probatio::{HwidCheck, Issuer, License, Verifier};

#[expect(clippy::print_stdout, clippy::use_debug)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = Issuer::new(&[0x42; 32]);

    let token = issuer.issue_claims(&License {
        lic: Some("L-2026-0001".into()),
        sku: Some("probatio-pro".into()),
        features: ["export".into(), "batch".into()].into(),
        iat: Some(1_800_000_000),
        hwid: Some(vec![0; 32]),
        ..Default::default()
    })?;
    println!("token: {} bytes", token.len());

    let license = Verifier::new(&issuer.public_key())?
        .verify(&token)?
        .claims::<License>()?;

    println!("verified: {license:?}");
    println!("active: {}", license.is_active_at(1_900_000_000));
    println!("hwid: {:?}", license.hwid_check(&[0; 32]));
    debug_assert_eq!(license.hwid_check(&[0; 32]), HwidCheck::Match);

    Ok(())
}
