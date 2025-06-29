use std::io::Write;
use std::path::PathBuf;
use std::ptr;

/// Zero out a string's memory contents
fn zero_string(s: &mut String) {
    unsafe {
        ptr::write_volatile(s.as_mut_ptr(), 0u8);
        for i in 1..s.len() {
            ptr::write_volatile(s.as_mut_ptr().add(i), 0u8);
        }
    }
    s.clear();
}

/// Temporary key pair for write operations
#[derive(Debug, Clone)]
pub struct TempKeyPair {
    pub private_key: String,
    pub public_key: String,
}

impl Drop for TempKeyPair {
    fn drop(&mut self) {
        zero_string(&mut self.private_key);
        zero_string(&mut self.public_key);
    }
}

/// Generate a temporary age key pair for write operations
pub fn generate_temp_age_key_pair(age_executable_path: &str) -> Result<TempKeyPair, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::{Command, Stdio};

    let output = Command::new(age_executable_path)
        .arg("--generate")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Age key generation failed: {}", error).into());
    }

    let output_str = String::from_utf8(output.stdout)?;
    let lines: Vec<&str> = output_str.lines().collect();

    if lines.len() < 2 {
        return Err("Invalid age key generation output".into());
    }

    let private_key = lines[0].trim().to_string();
    let public_key = lines[1].trim().to_string();

    Ok(TempKeyPair {
        private_key,
        public_key,
    })
}

/// Encrypt data with age public key
pub fn encrypt_with_age_public_key(data: &str, public_key: &str, age_executable_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(age_executable_path)
        .arg("-e")
        .arg("-r")
        .arg(public_key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdin = child.stdin.as_mut().ok_or("Failed to get stdin")?;
    stdin.write_all(data.as_bytes())?;
    drop(stdin); // Close stdin

    let output = child.wait_with_output()?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Age encryption failed: {}", error).into());
    }

    Ok(output.stdout)
}

/// Decrypt data with age private key
pub fn decrypt_with_age_private_key(age_executable_path: &str, file_path: &PathBuf, private_key: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(age_executable_path)
        .arg("-d")
        .arg("-i")
        .arg("-") // Read private key from stdin
        .arg(file_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdin = child.stdin.as_mut().ok_or("Failed to get stdin")?;
    stdin.write_all(private_key.as_bytes())?;
    drop(stdin); // Close stdin

    let output = child.wait_with_output()?;

    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Age decryption failed: {}", error).into());
    }

    let decrypted = String::from_utf8(output.stdout)?;
    Ok(decrypted)
} 