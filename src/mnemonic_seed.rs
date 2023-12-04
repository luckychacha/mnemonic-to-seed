use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;

pub struct MnemonicSeed {
    mnemonic: String,
    password: Option<String>,
}

// Number of iterations
const PBKDF2_ROUNDS: u32 = 2048;

// 512-bit seed
const PBKDF2_BYTES: usize = 64;

impl MnemonicSeed {
    pub fn new(mnemonic: String, password: Option<String>) -> Self {
        MnemonicSeed { mnemonic, password }
    }

    pub fn generate_seed(&self) -> [u8; PBKDF2_BYTES] {
        let salt = format!("mnemonic{}", self.password.clone().unwrap_or_default());
        let mut seed = [0u8; PBKDF2_BYTES];

        pbkdf2::<Hmac<Sha512>>(
            self.mnemonic.as_bytes(),
            salt.as_bytes(),
            PBKDF2_ROUNDS,
            &mut seed,
        )
        .expect("HMAC can be initialized with any key length");
        seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_seed() {
        let mnemonic =
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
                .to_string();
        let password = Some("TREZOR".to_string());
        let mnemonic_seed = MnemonicSeed::new(mnemonic, password);

        let seed = mnemonic_seed.generate_seed();
        assert_eq!(hex::encode(seed), "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607")
    }
}
