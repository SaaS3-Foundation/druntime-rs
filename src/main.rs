use ::abi::ABI;
use anyhow::{anyhow, Ok};
use ethabi::{
    decode, encode,
    param_type::{ParamType, Reader},
    token::{LenientTokenizer, StrictTokenizer, Token, Tokenizer},
    Contract, Event, Function, Hash,
};
use ethers::{
    abi::{AbiDecode, Tokenizable},
    prelude::*,
    solc::resolver::print,
    types::transaction::eip2718::TypedTransaction,
    utils::keccak256,
};
use ethers_signers::{coins_bip39::English, MnemonicBuilder};
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::{any, error::Error, fs::File};
use std::{collections::HashMap, env};
use structopt::StructOpt;

// Scheduler, trait for .seconds(), .minutes(), etc., and trait with job scheduling methods
use clokwerk::{AsyncScheduler, Job, TimeUnits};
use std::time::Duration;

// Define a struct called Opts
#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(short = "c", long = "cfg", default_value = "dev.ini")]
    cfg: PathBuf,
}

fn load_event(path: &str, name: &str) -> anyhow::Result<Event> {
    let file = File::open(path)?;
    let contract = Contract::load(file)?;
    let events = contract.events_by_name(name)?;
    match events.len() {
        0 => unreachable!(),
        1 => Ok(events[0].clone()),
        _ => Err(anyhow!(
            "More than one function found for name `{}`, try providing the full signature",
            name,
        )),
    }
}

// exammple
// let f = decode_log(
//    "./src/askv0.abi.json",
//    "Asked",
//    log.topics,
//    log.data.0.to_vec(),
//);
fn decode_log(
    path: &str,
    name: &str,
    topics: Vec<Hash>,
    data: Vec<u8>,
) -> anyhow::Result<ethabi::Log> {
    let event = load_event(path, name)?;
    let decoded = event.parse_log((topics, data).into())?;

    Ok(decoded)
}

fn identify_event(
    path: &str,
    topics: Vec<Hash>,
    data: Vec<u8>,
) -> anyhow::Result<(String, ethabi::Log)> {
    let file = File::open(path)?;
    let contract = Contract::load(file)?;
    let events = contract.events();
    for event in events {
        let decoded = event.parse_log((topics.clone(), data.clone()).into());
        if decoded.is_ok() {
            return Ok((event.name.to_owned(), decoded.unwrap()));
        }
    }
    Err(anyhow!("No event found"))
}

fn decode_url_params(log: &ethabi::Log) -> anyhow::Result<String> {
    let payload = log
        .params
        .iter()
        .find(|p| p.name == "payload")
        .unwrap()
        .value
        .clone();
    let b = match payload {
        Token::Bytes(content) => content,
        _ => anyhow::bail!("Invalid payload"),
    };

    let decoded_abi = ABI::decode_from_slice(&b, true).map_err(anyhow::Error::msg)?;
    let url_suffix = decoded_abi
        .params
        .iter()
        .filter(|param| !param.get_name().starts_with("_"))
        .map(|param| param.get_name().to_string() + "=" + &param.get_value().to_string())
        .collect::<Vec<String>>()
        .join("&");

    let url = "https://rpc.saas3.io:3301/saas3/web2/qatar2022/played?".to_string() + &url_suffix;
    Ok(url)
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
struct Network {
    http_provider: String,
    ws_provider: String,
    chain_id: u64,
    oracle_addr: String,
    block_offset: u64,
    gas_limit: u64,
    gas_price: u64,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
struct Oracle {
    abi: String,
    signer: String,
    interval: u32,
}
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
struct Config {
    title: String,
    network: Network,
    oracle: Oracle,
}

fn decode_askid(e: ethabi::Log) -> Result<U256, anyhow::Error> {
    let id = e
        .params
        .iter()
        .find(|p| p.name == "id")
        .unwrap()
        .value
        .clone();
    let id = match id {
        Token::Uint(content) => content,
        _ => {
            println!("invalid ask id");
            return Err(anyhow!("Invalid id"));
        }
    };
    Ok(id)
}

fn format_event(e: &ethabi::Log) -> String {
    e.params
        .iter()
        .map(|log_param| format!("{} {}", log_param.name, log_param.value))
        .collect::<Vec<String>>()
        .join("\n")
}

async fn submit_answer(cfg: &Config, ask_id: U256, answer: Vec<u8>) -> Result<(), anyhow::Error> {
    // SUBMIT
    let addr = cfg.network.oracle_addr.as_str().parse::<Address>().unwrap();
    println!("submitting answer to oracle {}", addr);

    let file = File::open("./src/askv0.abi.json")?;
    let abi: ethers::abi::Abi = serde_json::from_reader(file)?;

    let wallet = MnemonicBuilder::<English>::default()
        .phrase(cfg.oracle.signer.as_str())
        .build()?;

    println!("connect to http provider {}", cfg.network.http_provider);
    let provider = Provider::<Http>::try_from(&cfg.network.http_provider).unwrap();
    println!("provider: {}", provider.get_chainid().await?);
    let http_client = SignerMiddleware::new(provider, wallet.with_chain_id(cfg.network.chain_id));

    let mut gas_price = http_client.get_gas_price().await?;
    println!("gas price: {}", gas_price);
    if cfg.network.gas_price > 0 {
        println!("override gas price with {}", cfg.network.gas_price);
        gas_price = cfg.network.gas_price.into();
    }

    // create the contract object at the address
    let contract = ethers::contract::Contract::new(addr, abi, http_client.clone());

    // Non-constant methods are executed via the `send()` call on the method builder.
    println!("Calling `reply`...");
    let call = contract.method::<_, ()>("reply", (ask_id, Bytes::from(answer)))?;
    let eg = call.estimate_gas().await?;
    println!("eg: {}", eg);
    let mut gas_limit = eg * 10;
    if cfg.network.gas_limit > 0 {
        println!("override gas limit with {}", cfg.network.gas_limit);
        gas_limit = cfg.network.gas_limit.into();
    }
    println!("tx: {:?}", call.tx);
    let tx: TypedTransaction = TransactionRequest {
        from: None,
        to: call.tx.to().cloned(),
        nonce: None,
        value: None,
        gas: Some(gas_limit),
        gas_price: Some(gas_price),
        data: Some(call.tx.data().unwrap().clone()),
        chain_id: Some(cfg.network.chain_id.into()),
    }
    .into();
    let pending_tx = http_client.send_transaction(tx, None).await?;
    let receipt = pending_tx.confirmations(3).await?;

    // === old ===
    //    let receipt = call
    //        .gas(gas_limit)
    //        .gas_price(gas_price)
    //        .send()
    //        .await?
    //        .await?;
    // === old ===

    // `await`ing on the pending transaction resolves to a transaction receipt
    //let receipt = pending_tx.confirmations(6).await?;
    println!("receipt: {:#?}", receipt);

    Ok(())
}

async fn handle_log(cfg: &Config, log: Log) -> Result<(), anyhow::Error> {
    let (name, e) =
        identify_event("./src/askv0.abi.json", log.topics, log.data.0.to_vec()).unwrap();
    println!("Event: {} => \n{}", name, format_event(&e));

    match name.as_str() {
        "Asked" => {
            let url = decode_url_params(&e).unwrap();
            println!("url: {}", url);

            // do http request
            let mr: u32 = reqwest::get(url).await?.text().await?.parse().unwrap();
            println!("mr: {}", mr);

            let ask_id = decode_askid(e).unwrap();
            println!("ask_id: {}", ask_id);
            // encode reply payload
            let answer = ethabi::encode(&[ethabi::Token::Uint(U256::from(mr))]);
            submit_answer(cfg, ask_id, answer).await?;
        }
        "Replied" => {
            println!("Replied");
        }
        "ReplyFailed" => {
            println!(
                "ReplyFailed: {}",
                e.clone()
                    .params
                    .iter()
                    .find(|p| p.name == "errmsg")
                    .unwrap()
                    .value
                    .clone()
            );
        }
        _ => {
            println!("Unhandled event!");
        }
    }

    Ok(())
}

async fn execute(cfg: &Config) -> Result<(), anyhow::Error> {
    let wallet = MnemonicBuilder::<English>::default()
        .phrase(cfg.oracle.signer.as_str())
        .build()?;
    println!("Wallet: {}", wallet.address());

    println!("connecting to {}", cfg.network.ws_provider);
    let provider = Provider::<Ws>::connect(cfg.network.ws_provider.as_str()).await?;
    println!("provider: {}", provider.get_chainid().await?);
    assert_eq!(
        provider.get_chainid().await?,
        U256::from(cfg.network.chain_id)
    );

    println!("new client with signer");
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(cfg.network.chain_id));
    let client = Arc::new(client);

    println!("get latest block");
    let last_block = client
        .get_block(BlockNumber::Latest)
        .await?
        .unwrap()
        .number
        .unwrap();

    println!("last_block: {}", last_block);
    let from_block = last_block - cfg.network.block_offset;
    println!("from block: {}", from_block);

    let filter = Filter::new()
        .from_block(from_block)
        .address(cfg.network.oracle_addr.as_str().parse::<Address>().unwrap());

    println!("fetching events ...");
    let logs = client.get_logs(&filter).await?;
    for log in logs {
        handle_log(cfg, log).await?;
        println!("--------------------------------");
    }
    println!("fetching events done!");
    Ok(())
}

async fn run(cfg: Config) {
    println!("Start execute ...");
    let r = execute(&cfg).await;
    if r.is_err() {
        println!("Execute error: {}", r.unwrap_err());
    }
    println!("End execute ...");
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opts = Opts::from_args();
    println!("Using config file: {:?}", opts.cfg);
    let cfg: Config = confy::load_path(opts.cfg.to_str().unwrap())?;
    println!("Config: {:#?}", cfg.clone());
    let mut scheduler = AsyncScheduler::new();
    scheduler
        .every(cfg.oracle.interval.minutes())
        .run(move || run(cfg.clone()));
    // Manually run the scheduler forever
    loop {
        scheduler.run_pending().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
