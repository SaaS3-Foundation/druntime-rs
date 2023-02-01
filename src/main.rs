#![feature(let_chains)]
use ::abi::{encode::str_chunk32_bytes, ABI};
use anyhow::{anyhow, Ok};
use ethabi::{ethereum_types::U256, Hash};
use ethers::{
    prelude::*,
    types::transaction::eip2718::TypedTransaction,
    //utils::keccak256,
};
use ethers_signers::{ coins_bip39::English, MnemonicBuilder};
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use structopt::StructOpt;

// Scheduler, trait for .seconds(), .minutes(), etc., and trait with job scheduling methods
use clokwerk::{AsyncScheduler, TimeUnits};
use std::time::Duration;

// Define a struct called Opts
#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(short = "c", long = "cfg", default_value = "dev.ini")]
    cfg: PathBuf,
}

fn load_event(path: &str, name: &str) -> anyhow::Result<ethabi::Event> {
    let file = File::open(path)?;
    let contract = ethabi::Contract::load(file)?;
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
    topics: Vec<ethabi::Hash>,
    data: Vec<u8>,
) -> anyhow::Result<(String, ethabi::Log)> {
    let file = File::open(path)?;
    let contract = ethabi::Contract::load(file)?;
    let events = contract.events();
    for event in events {
        let decoded = event.parse_log((topics.clone(), data.clone()).into());
        if decoded.is_ok() {
            return Ok((event.name.to_owned(), decoded.unwrap()));
        }
    }
    Err(anyhow!("No event found"))
}

fn decode_abi(log: &ethabi::Log) -> anyhow::Result<ABI> {
    let payload = log
        .params
        .iter()
        .find(|p| p.name == "payload")
        .unwrap()
        .value
        .clone();
    let b = match payload {
        ethabi::token::Token::Bytes(content) => content,
        _ => anyhow::bail!("Invalid payload"),
    };

    Ok(ABI::decode_from_slice(&b, true).map_err(anyhow::Error::msg)?)
}

fn decode_url_params(log: &ethabi::Log) -> anyhow::Result<String> {
    let decoded_abi = decode_abi(log)?;
    let url_suffix = decoded_abi
        .params
        .iter()
        .filter(|param| !param.get_name().starts_with("_"))
        .map(|param| param.get_name().to_string() + "=" + &param.get_value().to_string())
        .collect::<Vec<String>>()
        .join("&");

    Ok(url_suffix)
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
struct Network {
    http_provider: String,
    chain_id: u64,
    oracle_addr: String,
    period: u64,
    from_block: Option<u64>,
    to_block: Option<u64>,
    gas_limit: Option<u64>,
    gas_price: Option<u64>,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
struct Oracle {
    abi: String,
    signer: String,
    interval: u32,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
struct Web2 {
    method: String,
    url: String,
    _path: String,
    _type: String,
    _times: u32,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
struct Config {
    title: Option<String>,
    network: Network,
    oracle: Oracle,
    web2: Web2,
}

fn decode_askid(e: ethabi::Log) -> Result<ethers::types::U256, anyhow::Error> {
    let id = e
        .params
        .iter()
        .find(|p| p.name == "id")
        .unwrap()
        .value
        .clone();
    let id = match id {
        ethabi::token::Token::Uint(content) => content,
        _ => {
            println!("invalid ask id");
            return Err(anyhow!("Invalid id"));
        }
    };
    Ok(ethers::types::U256::from(id.as_usize()))
}

fn format_event(e: &ethabi::Log) -> String {
    e.params
        .iter()
        .map(|log_param| format!("{} {}", log_param.name, log_param.value))
        .collect::<Vec<String>>()
        .join("\n")
}

async fn submit_answer(
    cfg: &Config,
    ask_id: ethers::types::U256,
    answer: Vec<u8>,
) -> Result<(), anyhow::Error> {
    // SUBMIT
    let addr = cfg.network.oracle_addr.as_str().parse::<Address>().unwrap();
    println!("submitting answer to oracle {}", addr);

    let file = File::open(&cfg.oracle.abi)?;
    let abi: ethers::abi::Abi = serde_json::from_reader(file)?;

    // if (cfg.oracle.signer.as_str().split(" "))

    let wallet = MnemonicBuilder::<English>::default()
        .phrase(cfg.oracle.signer.as_str())
        .build()?;

    

    println!("connect to http provider {}", cfg.network.http_provider);
    let provider = Provider::<Http>::try_from(&cfg.network.http_provider).unwrap();
    println!("provider: {}", provider.get_chainid().await?);

    let http_client = SignerMiddleware::new(
        provider, 
        wallet.with_chain_id(cfg.network.chain_id)
    );
    let accounts = http_client.get_accounts().await?;
    println!("{:#?}", accounts);
    // http_client.get_balance(from, block)
    let mut gas_price = http_client.get_gas_price().await?;
    println!("gas price: {}", gas_price);

    if let Some(gp) = cfg.network.gas_price && gp > 0 {
        println!("override gas price with {}", gp);
        gas_price = gp.into();
    }

    // create the contract object at the address
    let contract = ethers::contract::Contract::new(addr, abi, http_client.clone());

    // Non-constant methods are executed via the `send()` call on the method builder.
    println!("building `reply` tx... ask_id: {}", ask_id);
    let call = contract.method::<_, ()>("reply", (ask_id, Bytes::from(answer)))?;

    let eg = call.estimate_gas().await?;
    println!("estimate gas: {}", eg);

    let mut gas_limit = eg * 3;

    if let Some(gl) = cfg.network.gas_limit && gl > 0 {
        println!("override gas limit with {}", gl);
        gas_limit = gl.into();
    }

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

    println!("tx: {:?}", tx);

    let pending_tx = http_client.send_transaction(tx, None).await?;

    // `await`ing on the pending transaction resolves to a transaction receipt
    let receipt = pending_tx.confirmations(3).await?;

    // === old ===
    // works with eth, polygon, mooben alpha
    //    let receipt = call
    //        .gas(gas_limit)
    //        .gas_price(gas_price)
    //        .send()
    //        .await?
    //        .await?;
    // === old ===

    println!("receipt: {:#?}", receipt);

    Ok(())
}

fn read_by_path(v: serde_json::Value, path: &str) -> anyhow::Result<serde_json::Value> {
    println!("path: {}", path);
    let v = path
        .split(".")
        .fold(Ok(v), |v, p| {
            println!("p: {}", p);

            let v = v?
                .get(p)
                .ok_or(anyhow::anyhow!("failed to decode by path"))
                .cloned();
            v
        })
        .map_err(anyhow::Error::msg)?;

    println!("path {} value {:#?}", path, v);

    Ok(v)
}

fn encode_from_string_to_256(
    s: String,
    signed: bool,
    _times: u32,
) -> anyhow::Result<ethabi::Token> {
    let is_signed = s.starts_with("-");
    if is_signed && !signed {
        // eg. try encode "-3" to u256
        anyhow::bail!("number sign not match!")
    }
    let pos = s.find(".");
    if pos != None {
        // offset count
        let y = s.len() - pos.unwrap() - 1;

        if 10_u32.pow(y as u32) > _times {
            anyhow::bail!("_times too small ");
        }

        // remove decimal point
        let mut s = s.to_owned();
        s.retain(|c| c != '.' && c != '-');

        // alreay multiply by 10^y
        let mut v = s.parse::<u64>().unwrap();

        // times must >= 10^y
        v = v * (_times / 10_u32.pow(y as u32)) as u64;

        // encode to u256
        if is_signed {
            return Ok(ethabi::Token::Int(U256::from(v)));
        } else {
            return Ok(ethabi::Token::Uint(U256::from(v)));
        }
    } else {
        // not a decimal number
        let mut s = s.to_owned();
        s.retain(|c| c != '-');

        #[cfg(feature = "std")]
        println!("s: {}", s);

        if signed {
            s.parse::<i64>()
                .map(|x| ethabi::Token::Int(U256::from(x)))
                .map_err(anyhow::Error::msg)
        } else {
            s.parse::<u64>()
                .map(|x| ethabi::Token::Uint(U256::from(x)))
                .map_err(anyhow::Error::msg)
        }
    }
}

async fn encode_answer(
    v: serde_json::Value,
    _type: &str,
    _times: u32,
) -> Result<ethabi::Token, anyhow::Error> {
    match v {
        serde_json::Value::Number(n) => {
            return match _type {
                "string" => Ok(ethabi::Token::String(n.to_string())),
                "string32" => {
                    let chunk = str_chunk32_bytes(&n.to_string()).map_err(anyhow::Error::msg)?;
                    Ok(ethabi::Token::FixedBytes(chunk))
                }
                "uint256" => Ok(encode_from_string_to_256(n.to_string(), false, _times)?),
                "int256" => Ok(encode_from_string_to_256(n.to_string(), true, _times)?),
                _ => anyhow::bail!("invalid _type"),
            };
        }
        serde_json::Value::String(s) => {
            println!("String: {}", s);

            return match _type {
                "string" => Ok(ethabi::Token::String(s)),
                "string32" => {
                    let chunk = str_chunk32_bytes(&s.to_string()).map_err(anyhow::Error::msg)?;
                    Ok(ethabi::Token::FixedBytes(chunk))
                }
                "uint256" => Ok(encode_from_string_to_256(s, false, _times)?),
                "int256" => Ok(encode_from_string_to_256(s, true, _times)?),
                _ => anyhow::bail!("invalid type!"),
            };
        }
        _ => {
            anyhow::bail!("not a number or string!");
        }
    }
}

async fn get_answer(
    cfg: &Config,
    url: String,
    _type: String,
    _path: String,
    _times: u32,
) -> Result<ethabi::Token, anyhow::Error> {
    match cfg.web2.method.to_ascii_uppercase().as_str() {
        "GET" => {
            // do http request
            let res = reqwest::get(url).await?.text().await?;
            println!("{}", res);

            let root = serde_json::from_str::<serde_json::Value>(&res)
                .or(Err(anyhow!("failed to decode response json!")))?;

            println!("Got response {:#?}", root);

            let mut v = root.clone();
            println!("_path11: {}", _path);
            if _path != "" {
                v = read_by_path(root, &_path)?;
            } // no path, use the root path

            if v.is_array() || v.is_null() || v.is_object() {
                // we only support number, string, bool
                return Err(anyhow!("invald root value"));
            }
            println!("value: {}", v);
            return encode_answer(v, &_type, _times).await;
        }
        _ => Err(anyhow!("http method not support yet!")),
    }
}

async fn handle_log(cfg: &Config, log: Log) -> Result<(), anyhow::Error> {
    let (name, e) = identify_event(
        &cfg.oracle.abi,
        log.topics.iter().map(|t| ethabi::Hash::from(t.0)).collect(),
        log.data.0.to_vec(),
    )
    .unwrap();
    println!("Event: {} => \n{}", name, format_event(&e));

    match name.as_str() {
        "Asked" => {
            let url_suffix = decode_url_params(&e).unwrap();
            let decoded_abi = decode_abi(&e)?;
            // path is optional, if not set, we will use the root path
            let _path = decoded_abi
                .params
                .iter()
                .find(|param| param.get_name() == "_path")
                .get_or_insert(&::abi::Param::String {
                    name: "_path".to_string(),
                    value: cfg.web2._path.to_string(),
                })
                .get_value();

            println!("_path::::, {}", _path);

            // _type is necessary
            let _type = decoded_abi
                .params
                .iter()
                .find(|param| param.get_name() == "_type")
                .get_or_insert(&::abi::Param::String {
                    name: "_type".to_string(),
                    value: cfg.web2._type.to_string(),
                })
                //.ok_or(anyhow!("type not set"))?
                .get_value();

            // _times is only necessary for float number data
            let _times = decoded_abi
                .params
                .iter()
                .find(|param| param.get_name() == "_times")
                .get_or_insert(&::abi::Param::String {
                    name: "_times".to_string(),
                    value: cfg.web2._times.to_string(),
                })
                .get_value()
                .parse::<u32>()
                .map_err(anyhow::Error::msg)?;

            let url = cfg.web2.url.clone() + "?" + &url_suffix;
            println!("url: {}", url);
            
            let answer = get_answer(
                cfg,
                url,
                cfg.web2._type.clone(),
                cfg.web2._path.clone(),
                _times,
            )
            .await?;

            let ask_id = decode_askid(e).unwrap();
            println!("ask_id: {}", ask_id);

            // encode reply payload
            let answer = ethabi::encode(&[answer]);
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

    println!("connecting to {}", cfg.network.http_provider);
    let provider = Provider::<Http>::try_from(&cfg.network.http_provider).unwrap();
    println!("provider: {}", provider.get_chainid().await?);
    assert_eq!(
        provider.get_chainid().await?,
        ethers::types::U256::from(cfg.network.chain_id)
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

    let offset = 60 / cfg.network.period * (cfg.oracle.interval as u64);
    let mut from_block = last_block - offset;
    println!("from block: {}", from_block);

    if let Some(fb) = cfg.network.from_block && fb > 0 {
        println!("override from block with {}", fb);
        from_block = fb.into();
    }

    let mut filter = Filter::new()
        .from_block(from_block)
        .address(cfg.network.oracle_addr.as_str().parse::<Address>().unwrap());

    if let Some(tb) = cfg.network.to_block && tb > 0 {
        println!("set to block with {}", tb);
        filter = filter.to_block(tb);
    }

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
    println!("===== Start execute =====");
    let r = execute(&cfg).await;
    if r.is_err() {
        println!("Execute error: {}", r.unwrap_err());
    }
    println!("===== End execute =====");
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
