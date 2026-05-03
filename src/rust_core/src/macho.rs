use crate::error::LicenseError;
use std::ops::Range;

pub const LC_SEGMENT_64: u32 = 0x19;
pub const MH_MAGIC_64: u32 = 0xFEEDFACF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOSection {
    pub segment: String,
    pub section: String,
    pub file_range: Range<usize>,
}

pub fn find_section(
    payload: &[u8],
    segment_name: &str,
    section_name: &str,
) -> Result<MachOSection, LicenseError> {
    sections(payload)?
        .into_iter()
        .find(|section| section.segment == segment_name && section.section == section_name)
        .ok_or(LicenseError::RuntimeEnvironmentFailed)
}

pub fn sections(payload: &[u8]) -> Result<Vec<MachOSection>, LicenseError> {
    if payload.len() < 32 {
        return Err(LicenseError::RuntimeEnvironmentFailed);
    }

    if read_u32_le(payload, 0)? != MH_MAGIC_64 {
        return Err(LicenseError::RuntimeEnvironmentFailed);
    }

    let ncmds = read_u32_le(payload, 16)? as usize;
    let mut offset = 32usize;
    let mut sections = Vec::new();

    for _ in 0..ncmds {
        let cmd = read_u32_le(payload, offset)?;
        let cmdsize = read_u32_le(payload, offset + 4)? as usize;
        if cmdsize < 8 {
            return Err(LicenseError::RuntimeEnvironmentFailed);
        }

        let end = offset
            .checked_add(cmdsize)
            .ok_or(LicenseError::RuntimeEnvironmentFailed)?;
        if end > payload.len() {
            return Err(LicenseError::RuntimeEnvironmentFailed);
        }

        if cmd == LC_SEGMENT_64 {
            if cmdsize < 72 {
                return Err(LicenseError::RuntimeEnvironmentFailed);
            }

            let segname = read_fixed_name(payload, offset + 8)?.to_string();
            let nsects = read_u32_le(payload, offset + 64)? as usize;
            let mut section_offset = offset + 72;

            for _ in 0..nsects {
                let section_end = section_offset
                    .checked_add(80)
                    .ok_or(LicenseError::RuntimeEnvironmentFailed)?;
                if section_end > end {
                    return Err(LicenseError::RuntimeEnvironmentFailed);
                }

                let sectname = read_fixed_name(payload, section_offset)?.to_string();
                let section_segname = read_fixed_name(payload, section_offset + 16)?.to_string();
                if section_segname != segname {
                    return Err(LicenseError::RuntimeEnvironmentFailed);
                }

                let size = read_u64_le(payload, section_offset + 40)? as usize;
                let file_offset = read_u32_le(payload, section_offset + 48)? as usize;
                let file_end = file_offset
                    .checked_add(size)
                    .ok_or(LicenseError::RuntimeEnvironmentFailed)?;
                if file_end > payload.len() {
                    return Err(LicenseError::RuntimeEnvironmentFailed);
                }

                sections.push(MachOSection {
                    segment: segname.clone(),
                    section: sectname,
                    file_range: file_offset..file_end,
                });

                section_offset = section_end;
            }
        }

        offset = end;
    }

    Ok(sections)
}

fn read_fixed_name(payload: &[u8], offset: usize) -> Result<&str, LicenseError> {
    let end = offset
        .checked_add(16)
        .ok_or(LicenseError::RuntimeEnvironmentFailed)?;
    let raw = payload
        .get(offset..end)
        .ok_or(LicenseError::RuntimeEnvironmentFailed)?;
    let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());

    std::str::from_utf8(&raw[..nul]).map_err(|_| LicenseError::RuntimeEnvironmentFailed)
}

pub fn read_u32_le(payload: &[u8], offset: usize) -> Result<u32, LicenseError> {
    let end = offset
        .checked_add(4)
        .ok_or(LicenseError::RuntimeEnvironmentFailed)?;
    let bytes = payload
        .get(offset..end)
        .ok_or(LicenseError::RuntimeEnvironmentFailed)?;

    Ok(u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| LicenseError::RuntimeEnvironmentFailed)?,
    ))
}

fn read_u64_le(payload: &[u8], offset: usize) -> Result<u64, LicenseError> {
    let end = offset
        .checked_add(8)
        .ok_or(LicenseError::RuntimeEnvironmentFailed)?;
    let bytes = payload
        .get(offset..end)
        .ok_or(LicenseError::RuntimeEnvironmentFailed)?;

    Ok(u64::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| LicenseError::RuntimeEnvironmentFailed)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{LC_SEGMENT_64, MH_MAGIC_64, find_section};

    #[test]
    fn locates_section_in_synthetic_macho() {
        let macho = synthetic_macho_with_license_section();
        let section = find_section(&macho, "__TEXT", "__license").unwrap();

        assert_eq!(section.file_range, 192..196);
        assert_eq!(&macho[section.file_range], b"SLC1");
    }

    fn synthetic_macho_with_license_section() -> Vec<u8> {
        let mut payload = vec![0u8; 224];

        payload[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        payload[16..20].copy_from_slice(&(1u32).to_le_bytes());

        payload[32..36].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        payload[36..40].copy_from_slice(&(152u32).to_le_bytes());
        write_fixed_name(&mut payload, 40, "__TEXT");
        payload[96..100].copy_from_slice(&(1u32).to_le_bytes());

        write_fixed_name(&mut payload, 104, "__license");
        write_fixed_name(&mut payload, 120, "__TEXT");
        payload[144..152].copy_from_slice(&(4u64).to_le_bytes());
        payload[152..156].copy_from_slice(&(192u32).to_le_bytes());
        payload[192..196].copy_from_slice(b"SLC1");

        payload
    }

    fn write_fixed_name(payload: &mut [u8], offset: usize, name: &str) {
        let bytes = name.as_bytes();
        payload[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
}
