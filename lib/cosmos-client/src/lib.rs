#![allow(async_fn_in_trait)]

use anyhow::{anyhow, bail, Context, Result};
use cometbft_rpc::rpc_types::TxResponse;
use protos::cosmos::base::abci;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tracing::{debug, info};
use unionlabs::{
    cosmos::{
        auth::base_account::BaseAccount,
        base::{abci::gas_info::GasInfo, coin::Coin},
        crypto::{secp256k1, AnyPubKey},
        tx::{
            auth_info::AuthInfo, fee::Fee, mode_info::ModeInfo, sign_doc::SignDoc,
            signer_info::SignerInfo, signing::sign_info::SignMode, tx::Tx, tx_body::TxBody,
            tx_raw::TxRaw,
        },
    },
    encoding::{EncodeAs, Proto},
    google::protobuf::any::Any,
    primitives::H256,
    prost::{Message, Name},
    signer::CosmosSigner,
};

use crate::{gas::GasFillerT, rpc::RpcT, wallet::WalletT};

pub mod gas;
pub mod rpc;
pub mod wallet;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct GasConfig {
    pub gas_price: f64,
    pub gas_denom: String,
    pub gas_multiplier: f64,
    pub max_gas: u64,
    pub min_gas: u64,
}

impl GasConfig {
    pub fn mk_fee(&self, gas: u64) -> Fee {
        // gas limit = provided gas * multiplier, clamped between min_gas and max_gas
        let gas_limit = u128_saturating_mul_f64(gas.into(), self.gas_multiplier)
            .clamp(self.min_gas.into(), self.max_gas.into());

        let amount = u128_saturating_mul_f64(gas.into(), self.gas_price);

        Fee {
            amount: vec![Coin {
                amount,
                denom: self.gas_denom.clone(),
            }],
            gas_limit: gas_limit.try_into().unwrap_or(u64::MAX),
            payer: String::new(),
            granter: String::new(),
        }
    }
}

fn u128_saturating_mul_f64(u: u128, f: f64) -> u128 {
    (num_rational::BigRational::from_integer(u.into())
        * num_rational::BigRational::from_float(f).expect("finite"))
    .to_integer()
    .try_into()
    .unwrap_or(u128::MAX)
    // .expect("overflow")
}

pub struct TxClient<W, Q, G> {
    wallet: W,
    rpc: Q,
    gas: G,
}

impl<W, Q, G> TxClient<W, Q, G> {
    pub fn new(wallet: W, rpc: Q, gas: G) -> Self {
        Self { wallet, rpc, gas }
    }
}

impl<W: WalletT, Q: RpcT, G: GasFillerT> TxClient<W, Q, G> {
    pub async fn tx<M: Message + Name, R: Message + Default + Name>(
        &self,
        msg: M,
        memo: impl AsRef<str>,
    ) -> Result<(H256, R)> {
        let (tx_hash, result) = self
            .broadcast_tx_commit(
                [protos::google::protobuf::Any {
                    type_url: M::type_url(),
                    value: msg.encode_to_vec().into(),
                }],
                memo,
            )
            .await
            .context("broadcast_tx_commit")?;

        let response =
            <abci::v1beta1::TxMsgData as Message>::decode(&*result.tx_result.data.unwrap())
                .unwrap();

        assert_eq!(&*response.msg_responses[0].type_url, R::type_url());

        let response =
            R::decode(&*response.msg_responses[0].value).context("parsing returned address")?;

        Ok((tx_hash, response))
    }

    /// - simulate tx
    /// - submit tx
    /// - wait for inclusion
    /// - return (tx_hash, gas_used)
    async fn broadcast_tx_commit(
        &self,
        messages: impl IntoIterator<Item = protos::google::protobuf::Any> + Clone,
        memo: impl AsRef<str>,
    ) -> Result<(H256, TxResponse)> {
        let account = self
            .account_info(&self.wallet.signer().to_string())
            .await
            .context("fetching account info")?;

        let (tx_body, mut auth_info, simulation_gas_info) = self
            .simulate_tx(messages, memo)
            .await
            .context("simulate_tx")?;

        info!(
            gas_used = %simulation_gas_info.gas_used,
            gas_wanted = %simulation_gas_info.gas_wanted,
            "tx simulation successful"
        );

        auth_info.fee = self.gas.mk_fee(simulation_gas_info.gas_used).await;

        info!(
            fee = %auth_info.fee.amount[0].amount,
            // gas_multiplier = %self.gas_config.gas_multiplier,
            "submitting transaction with gas"
        );

        // re-sign the new auth info with the simulated gas
        let signature = self
            .wallet
            .signer()
            .try_sign(
                &SignDoc {
                    body_bytes: tx_body.clone().encode_as::<Proto>(),
                    auth_info_bytes: auth_info.clone().encode_as::<Proto>(),
                    chain_id: self.rpc.chain_id().to_string(),
                    account_number: account.account_number,
                }
                .encode_as::<Proto>(),
            )
            .expect("signing failed")
            .to_bytes()
            .to_vec();

        let tx_raw_bytes = TxRaw {
            body_bytes: tx_body.clone().encode_as::<Proto>(),
            auth_info_bytes: auth_info.clone().encode_as::<Proto>(),
            signatures: [signature].to_vec(),
        }
        .encode_as::<Proto>();

        let tx_hash: H256 = sha2::Sha256::new()
            .chain_update(&tx_raw_bytes)
            .finalize()
            .into();

        if let Ok(tx) = self.rpc.client().tx(tx_hash, false).await {
            debug!(%tx_hash, "tx already included");
            return Ok((tx_hash, tx));
        }

        let response = self
            .rpc
            .client()
            .broadcast_tx_sync(&tx_raw_bytes)
            .await
            .context("broadcast_tx_sync")?;

        assert_eq!(tx_hash, response.hash, "tx hash calculated incorrectly");

        info!(%tx_hash);

        info!(
            check_tx_code = %response.code,
            codespace = %response.codespace,
            check_tx_log = %response.log
        );

        if response.code > 0 {
            bail!(
                "cosmos tx failed: {}, {}: {}",
                response.code,
                response.codespace,
                response.log
            );
        };

        let mut target_height = self
            .rpc
            .client()
            .block(None)
            .await
            .context("querying latest block")?
            .block
            .header
            .height;

        let mut i = 0;
        loop {
            let reached_height = 'l: loop {
                let current_height = self
                    .rpc
                    .client()
                    .block(None)
                    .await
                    .context("querying latest block for tx inclusion")?
                    .block
                    .header
                    .height;

                if current_height >= target_height {
                    break 'l current_height;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            };

            let tx_inclusion = self.rpc.client().tx(tx_hash, false).await;

            // debug!(?tx_inclusion);

            match tx_inclusion {
                Ok(tx) => {
                    if tx.tx_result.code == 0 {
                        break Ok((tx_hash, tx));
                    } else {
                        bail!(
                            "cosmos tx failed: {}, {}: {}",
                            response.code,
                            response.codespace,
                            response.log
                        );
                    }
                }
                Err(err) if i > 5 => {
                    return Err(anyhow!(
                        "tx inclusion couldn't be retrieved after {i} attempt(s) (tx hash: {tx_hash})"
                    )
                    .context(err));
                }
                Err(_) => {
                    debug!("unable to retrieve tx inclusion, trying again");
                    target_height = reached_height.add(&1);
                    i += 1;
                    continue;
                }
            }
        }
    }

    async fn simulate_tx(
        &self,
        messages: impl IntoIterator<Item = protos::google::protobuf::Any> + Clone,
        memo: impl AsRef<str>,
    ) -> Result<(TxBody, AuthInfo, GasInfo)> {
        use protos::cosmos::tx;

        let account = self
            .account_info(&self.wallet.signer().to_string())
            .await
            .context("querying account info")?;

        let tx_body = TxBody {
            // TODO: Use RawAny here
            messages: messages.clone().into_iter().map(Into::into).collect(),
            memo: memo.as_ref().to_owned(),
            timeout_height: 0,
            extension_options: vec![],
            non_critical_extension_options: vec![],
            unordered: false,
            timeout_timestamp: None,
        };

        let auth_info = AuthInfo {
            signer_infos: [SignerInfo {
                public_key: Some(AnyPubKey::Secp256k1(secp256k1::PubKey {
                    key: self.wallet.signer().public_key().into(),
                })),
                mode_info: ModeInfo::Single {
                    mode: SignMode::Direct,
                },
                sequence: account.sequence,
            }]
            .to_vec(),
            fee: self.gas.mk_fee(self.gas.max_gas().await).await,
        };

        let simulation_signature = self
            .wallet
            .signer()
            .try_sign(
                &SignDoc {
                    body_bytes: tx_body.clone().encode_as::<Proto>(),
                    auth_info_bytes: auth_info.clone().encode_as::<Proto>(),
                    chain_id: self.rpc.chain_id().to_string(),
                    account_number: account.account_number,
                }
                .encode_as::<Proto>(),
            )
            .expect("signing failed")
            .to_bytes()
            .to_vec();

        let simulate_response = self
            .rpc
            .client()
            .grpc_abci_query::<_, tx::v1beta1::SimulateResponse>(
                "/cosmos.tx.v1beta1.Service/Simulate",
                &tx::v1beta1::SimulateRequest {
                    tx_bytes: Tx {
                        body: tx_body.clone(),
                        auth_info: auth_info.clone(),
                        signatures: [simulation_signature.clone()].to_vec(),
                    }
                    .encode_as::<Proto>(),
                    ..Default::default()
                },
                None,
                false,
            )
            .await
            .context("submitting SimulateRequest")?
            .into_result()?;

        let result = simulate_response.unwrap();

        Ok((
            tx_body,
            auth_info,
            result
                .gas_info
                .expect("gas info is present on successful simulation result")
                .into(),
        ))
    }

    async fn account_info(&self, account: &str) -> Result<BaseAccount> {
        debug!(%account, "fetching account");

        Ok(self
            .rpc
            .client()
            .grpc_abci_query::<_, protos::cosmos::auth::v1beta1::QueryAccountResponse>(
                "/cosmos.auth.v1beta1.Query/Account",
                &protos::cosmos::auth::v1beta1::QueryAccountRequest {
                    address: account.to_string(),
                },
                None,
                false,
            )
            .await
            .context("querying account info")?
            .into_result()?
            .unwrap()
            .account
            .map(<Any<BaseAccount>>::try_from)
            .context("decoding account info")??
            .0)
    }
}

impl RpcT for Ctx {
    fn client(&self) -> &cometbft_rpc::Client {
        &self.client
    }

    fn chain_id(&self) -> &str {
        &self.chain_id
    }
}

impl WalletT for Ctx {
    fn signer(&self) -> &CosmosSigner {
        &self.signer
    }
}

impl GasFillerT for Ctx {
    async fn max_gas(&self) -> u64 {
        self.gas_config.max_gas
    }

    async fn mk_fee(&self, gas: u64) -> Fee {
        self.gas_config.mk_fee(gas)
    }
}

impl Ctx {
    pub async fn new(rpc_url: String, private_key: H256, gas_config: GasConfig) -> Result<Ctx> {
        let client = cometbft_rpc::Client::new(rpc_url)
            .await
            .context("creating cometbft rpc client")?;

        let prefix = client
            .grpc_abci_query::<_, protos::cosmos::auth::v1beta1::Bech32PrefixResponse>(
                "/cosmos.auth.v1beta1.Query/Bech32Prefix",
                &protos::cosmos::auth::v1beta1::Bech32PrefixRequest {},
                None,
                false,
            )
            .await
            .context("querying bech32 prefix")?
            .into_result()?
            .unwrap()
            .bech32_prefix;

        let chain_id = client
            .status()
            .await
            .context("querying node status")?
            .node_info
            .network;

        let ctx = Ctx {
            signer: CosmosSigner::new(
                bip32::secp256k1::ecdsa::SigningKey::from_bytes(&private_key.into())
                    .expect("invalid private key"),
                prefix,
            ),
            client,
            gas_config,
            chain_id,
        };

        Ok(ctx)
    }

    pub fn gas_config(&self) -> &GasConfig {
        &self.gas_config
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }
}
