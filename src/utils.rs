use anyhow::{Context, Result};
use std::io::Read;
use std::path::Path;

pub fn read_vectors_from_zip(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let mut combined_vectors = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
            combined_vectors.push(value);
        }
    }

    if combined_vectors.is_empty() {
        anyhow::bail!("No valid JSON files found in ZIP archive");
    }

    serde_json::to_string(&serde_json::Value::Array(combined_vectors))
        .context("Failed to serialize combined vectors")
}

#[allow(dead_code)]
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    hex::decode(hex).context("Invalid hex string")
}

#[allow(dead_code)]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_hex_to_bytes() {
        let hex = "deadbeef";
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_bytes_to_hex() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "deadbeef");
    }

    #[test]
    fn test_hex_round_trip() {
        let original = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = bytes_to_hex(&original);
        let decoded = hex_to_bytes(&hex).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_invalid_hex() {
        let result = hex_to_bytes("not hex!");
        assert!(result.is_err());
    }

    #[test]
    fn test_read_vectors_from_zip() -> Result<()> {
        use std::fs::File;
        use zip::write::{FileOptions, ZipWriter};

        // Create a temporary ZIP file with test vectors
        let temp_dir = std::env::temp_dir();
        let zip_path = temp_dir.join("test_vectors.zip");

        {
            let file = File::create(&zip_path)?;
            let mut zip = ZipWriter::new(file);

            let test_vector = r#"{"algorithm": "SHA2-256", "vsId": 1}"#;
            zip.start_file("test1.json", FileOptions::<()>::default())?;
            zip.write_all(test_vector.as_bytes())?;

            zip.finish()?;
        }

        let result = read_vectors_from_zip(&zip_path);
        assert!(result.is_ok());

        // Clean up
        let _ = std::fs::remove_file(zip_path);

        Ok(())
    }
}
