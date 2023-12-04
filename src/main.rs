use crate::mnemonic_seed::MnemonicSeed;

mod mnemonic_seed;

fn main() {
    let mnemonic =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
            .to_string();
    let password = Some("TREZOR".to_string());
    let mnemonic_seed = MnemonicSeed::new(mnemonic, password);

    let seed = mnemonic_seed.generate_seed();
    assert_eq!(
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
        hex::encode(seed)
    );
}
