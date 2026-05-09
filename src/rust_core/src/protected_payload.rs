use crate::capability::Capability;
use crate::error::LicenseError;
use crate::policy::{PolicyClaims, ProtectedPayloadBlock};

pub fn run(capability: &mut Capability, claims: &PolicyClaims) -> Result<(), LicenseError> {
    let phase_one = decrypt_utf8_stage(capability, claims, 1)?;
    let phase_one_code = derive_display_token(0xB0B0_0001, &phase_one);
    println!("{phase_one} [wire={phase_one_code:08x}]");

    let rules = decrypt_utf8_stage(capability, claims, 2)?;
    let score = score_rules(&rules);
    let phase_two_code = derive_display_token(score, &rules);
    println!("phase 2 defused: sealed rule score={score} route={phase_two_code:08x}");

    let final_banner = decrypt_utf8_stage(capability, claims, 3)?;
    let final_token = derive_display_token(score ^ phase_one_code, &final_banner);
    println!("{final_banner} [score={score} token={final_token:08x}]");
    println!("bomb defused: capability chain consumed 3 encrypted stages");

    Ok(())
}

fn decrypt_utf8_stage(
    capability: &mut Capability,
    claims: &PolicyClaims,
    block_id: u64,
) -> Result<String, LicenseError> {
    let block = find_block(claims, block_id)?;
    let plaintext = capability.decrypt_block(block)?;

    String::from_utf8(plaintext).map_err(|_| LicenseError::RuntimeConstraintViolation)
}

fn find_block(
    claims: &PolicyClaims,
    block_id: u64,
) -> Result<&ProtectedPayloadBlock, LicenseError> {
    claims
        .protected_payload
        .iter()
        .find(|block| block.block_id == block_id)
        .ok_or(LicenseError::RuntimeConstraintViolation)
}

fn score_rules(rules: &str) -> u32 {
    rules
        .bytes()
        .enumerate()
        .fold(0x6424u32, |acc, (idx, byte)| {
            acc.rotate_left(5) ^ ((byte as u32) + ((idx as u32) << 3))
        })
}

fn derive_display_token(score: u32, template: &str) -> u32 {
    template.bytes().fold(score ^ 0xC0DE_6424, |acc, byte| {
        acc.rotate_right(3) ^ byte as u32
    })
}
