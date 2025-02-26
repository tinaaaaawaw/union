use unionlabs::signer::CosmosSigner;

pub trait WalletT {
    fn signer(&self) -> &CosmosSigner;
}
