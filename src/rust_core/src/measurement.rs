use crate::error::LicenseError;
use crate::macho;
use sha2::{Digest, Sha256};

const MEASURED_SECTIONS: &[(&str, &str)] = &[
    ("__TEXT", "__text"),
    ("__TEXT", "__stubs"),
    ("__TEXT", "__cstring"),
    ("__TEXT", "__const"),
    ("__TEXT", "__gcc_except_tab"),
    ("__TEXT", "__unwind_info"),
    ("__TEXT", "__eh_frame"),
    ("__DATA_CONST", "__got"),
    ("__DATA_CONST", "__const"),
];

pub fn hash_executable_image(payload: &[u8]) -> Result<[u8; 32], LicenseError> {
    let sections = macho::sections(payload)?;
    let mut hasher = Sha256::new();

    hasher.update(b"COMS6424_EXECUTABLE_IMAGE_V2");

    for &(segment, section) in MEASURED_SECTIONS {
        let Some(macho_section) = sections
            .iter()
            .find(|candidate| candidate.segment == segment && candidate.section == section)
        else {
            continue;
        };

        let bytes = payload
            .get(macho_section.file_range.clone())
            .ok_or(LicenseError::RuntimeEnvironmentFailed)?;

        hasher.update(segment.as_bytes());
        hasher.update([0]);
        hasher.update(section.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::hash_executable_image;
    use crate::macho::{LC_SEGMENT_64, MH_MAGIC_64};

    #[test]
    fn hash_changes_when_measured_text_changes() {
        let mut first = synthetic_macho_with_text_section(b"ABCD");
        let mut second = first.clone();
        second[192] = b'Z';

        let first_hash = hash_executable_image(&first).unwrap();
        let second_hash = hash_executable_image(&second).unwrap();

        assert_ne!(first_hash, second_hash);

        first[200] = b'Z';
        assert_eq!(first_hash, hash_executable_image(&first).unwrap());
    }

    fn synthetic_macho_with_text_section(text: &[u8; 4]) -> Vec<u8> {
        let mut payload = vec![0u8; 224];

        payload[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        payload[16..20].copy_from_slice(&(1u32).to_le_bytes());

        payload[32..36].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        payload[36..40].copy_from_slice(&(152u32).to_le_bytes());
        write_fixed_name(&mut payload, 40, "__TEXT");
        payload[96..100].copy_from_slice(&(1u32).to_le_bytes());

        write_fixed_name(&mut payload, 104, "__text");
        write_fixed_name(&mut payload, 120, "__TEXT");
        payload[144..152].copy_from_slice(&(4u64).to_le_bytes());
        payload[152..156].copy_from_slice(&(192u32).to_le_bytes());
        payload[192..196].copy_from_slice(text);

        payload
    }

    fn write_fixed_name(payload: &mut [u8], offset: usize, name: &str) {
        let bytes = name.as_bytes();
        payload[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
}
