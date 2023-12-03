use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;
use std::fmt::Write;

struct MnemonicSeed {
    mnemonic: String,
    password: Option<String>,
}

// Number of iterations
const PBKDF2_ROUNDS: u32 = 2048;

// 512-bit seed
const PBKDF2_BYTES: usize = 64;

impl MnemonicSeed {
    fn new(mnemonic: String, password: Option<String>) -> Self {
        MnemonicSeed { mnemonic, password }
    }

    fn generate_seed(&self) -> [u8; PBKDF2_BYTES] {
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

fn main() {
    let mnemonic = "example mnemonic phrase here".to_string();
    let password = Some("optional password".to_string());
    let mnemonic_seed = MnemonicSeed::new(mnemonic, password);

    let seed = mnemonic_seed.generate_seed();
    println!("Seed: {:?}", hex::encode(seed));
}
