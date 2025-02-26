pub trait RpcT {
    fn client(&self) -> &cometbft_rpc::Client;

    // TODO: Better type here
    fn chain_id(&self) -> &str;
}

#[derive(Debug, Clone)]
pub struct Rpc {
    client: cometbft_rpc::Client,
    chain_id: String,
}

impl RpcT for Rpc {
    fn client(&self) -> &cometbft_rpc::Client {
        &self.client
    }

    fn chain_id(&self) -> &str {
        &self.chain_id
    }
}
