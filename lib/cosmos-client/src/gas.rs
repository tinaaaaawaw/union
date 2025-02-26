use unionlabs::cosmos::tx::fee::Fee;

pub trait GasFillerT {
    async fn max_gas(&self) -> u64;

    async fn mk_fee(&self, gas: u64) -> Fee;
}
