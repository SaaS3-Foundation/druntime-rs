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
    utils::keccak256,
};
use ethers_signers::{coins_bip39::English, MnemonicBuilder};
use eyre::Result;
use std::env;
use std::sync::Arc;
use std::{any, error::Error, fs::File};

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

    println!("Payload: {}", hex::encode(&b));
    let decoded_abi = ABI::decode_from_slice(&b, true).map_err(anyhow::Error::msg)?;
    let url_suffix = decoded_abi
        .params
        .iter()
        .filter(|param| !param.get_name().starts_with("_"))
        .map(|param| param.get_name().to_string() + "=" + &param.get_value().to_string())
        .collect::<Vec<String>>()
        .join("&");
    println!("{}", url_suffix);

    let url = "http://150.109.145.144:3301/saas3/web2/qatar2022/played?".to_string() + &url_suffix;
    Ok(url)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let wallet = MnemonicBuilder::<English>::default()
        .phrase("aisle genuine false door mouse sustain caught flock pyramid sister scan disease")
        .build()?;
    println!("Wallet: {}", wallet.address());
    let provider =
        Provider::<Ws>::connect("wss://goerli.infura.io/ws/v3/e5cbadfb7319409f981ee0231c256639")
            .await?;
    // let client = Arc::new(client);
    let client = SignerMiddleware::new(provider, wallet.with_chain_id(5 as u64));
    let client = Arc::new(client);

    let last_block = client
        .get_block(BlockNumber::Latest)
        .await?
        .unwrap()
        .number
        .unwrap();
    println!("last_block: {}", last_block);

    let filter = Filter::new().from_block(last_block - 5).address(
        "0x8c29859d9589509a57A090716E1d7E700eF2DF8c"
            .parse::<Address>()
            .unwrap(),
    );
    let mut stream = client.subscribe_logs(&filter).await?;
    println!("{:?}", env::current_dir());
    load_event("./src/askv0.abi.json", "Asked").unwrap();
    let s: String = reqwest::get("https://www.baidu.com")
        .await?
        .text()
        .await?
        .parse()
        .unwrap();

    while let Some(log) = stream.next().await {
        println!("log: {:#?}", log);
        //let f = decode_log(
        //    "./src/askv0.abi.json",
        //    "Asked",
        //    log.topics,
        //    log.data.0.to_vec(),
        //);
        let (name, f) =
            identify_event("./src/askv0.abi.json", log.topics, log.data.0.to_vec()).unwrap();
        let result = f
            .clone()
            .params
            .into_iter()
            .map(|log_param| format!("{} {}", log_param.name, log_param.value))
            .collect::<Vec<String>>()
            .join("\n");
        println!("{}", result);
        match name.as_str() {
            "Asked" => {
                println!("Asked");
                let url = decode_url_params(&f).unwrap();
                //let mr: u32 = reqwest::get(url).await?.text().await?.parse().unwrap();
                //println!("mr: {}", mr);
                // submit result

                let addr = "0x8c29859d9589509a57A090716E1d7E700eF2DF8c"
                    .parse::<Address>()
                    .unwrap();

                abigen!(
                    SimpleContract,
                    "./src/askv0.abi.json",
                    event_derives(serde::Deserialize, serde::Serialize)
                );
                let id = f
                    .params
                    .iter()
                    .find(|p| p.name == "id")
                    .unwrap()
                    .value
                    .clone();
                let id = match id {
                    Token::Uint(content) => content,
                    _ => {
                        println!("invalid id");
                        return Ok(());
                    }
                };
                let data = ethabi::encode(&[ethabi::Token::Uint(U256::from(1))]);

                let contract = SimpleContract::new(addr, client.clone());
                let r = contract
                    .reply(U256::from(id), Bytes::from(data))
                    .send()
                    .await?
                    .await?;
                println!("r: {:#?}", r);
            }
            "Replied" => {
                println!("Replied");
            }
            "ReplyFailed" => {
                println!(
                    "ReplyFailed: {}",
                    f.params
                        .iter()
                        .find(|p| p.name == "errmsg")
                        .unwrap()
                        .value
                        .clone()
                );
            }
            _ => {
                println!("Unknown event");
            }
        }
    }

    Ok(())
}
