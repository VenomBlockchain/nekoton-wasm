#![allow(clippy::unused_unit)]

use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use ed25519_dalek::{Signer, Verifier};
use nt::abi::FunctionExt;
use nt::utils::Clock;
use ton_block::{Deserializable, GetRepresentationHash, Serializable};
use ton_executor::TransactionExecutor;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue};
use zeroize::Zeroize;

use crate::models::*;
use crate::tokens_object::*;
use crate::utils::*;

mod external;
mod generic_contract;
mod models;
mod tokens_object;
mod transport;
mod utils;

#[wasm_bindgen(js_name = "checkAddress")]
pub fn check_address(address: &str) -> bool {
    nt::utils::validate_address(address)
}

#[wasm_bindgen(js_name = "repackAddress")]
pub fn repack_address(address: &str) -> Result<String, JsValue> {
    nt::utils::repack_address(address)
        .map(|x| x.to_string())
        .handle_error()
}

#[wasm_bindgen(js_name = "runLocal")]
pub fn run_local(
    clock: &ClockWithOffset,
    account_stuff_boc: &str,
    contract_abi: &str,
    method: &str,
    input: TokensObject,
    responsible: bool,
) -> Result<ExecutionOutput, JsValue> {
    let account_stuff = parse_account_stuff(account_stuff_boc)?;
    let contract_abi = parse_contract_abi(contract_abi)?;
    let method = contract_abi.function(method).handle_error()?;
    let input = parse_tokens_object(&method.inputs, input).handle_error()?;

    let output = if responsible {
        method
            .run_local_responsible(clock.inner.as_ref(), account_stuff, &input)
            .handle_error()?
    } else {
        method
            .run_local(clock.inner.as_ref(), account_stuff, &input)
            .handle_error()?
    };

    make_execution_output(output)
}

#[wasm_bindgen(js_name = "makeFullAccountBoc")]
pub fn make_full_account_boc(account_stuff_boc: &str) -> Result<String, JsValue> {
    let account_stuff = parse_account_stuff(account_stuff_boc)?;
    ton_block::Account::Account(account_stuff)
        .serialize()
        .and_then(|cell| ton_types::serialize_toc(&cell))
        .map(base64::encode)
        .handle_error()
}

#[wasm_bindgen(js_name = "parseFullAccountBoc")]
pub fn parse_full_account_boc(account: &str) -> Result<OptionFullContractState, JsValue> {
    let account = parse_cell(account)?;
    let account = if nt::utils::is_empty_cell(&account.repr_hash()) {
        nt::transport::models::RawContractState::NotExists
    } else {
        match ton_block::Account::construct_from_cell(account).handle_error()? {
            ton_block::Account::Account(account) => {
                let last_transaction_id = nt::abi::LastTransactionId::Inexact {
                    latest_lt: account.storage.last_trans_lt,
                };
                nt::transport::models::RawContractState::Exists(
                    nt::transport::models::ExistingContract {
                        account,
                        timings: nt::abi::GenTimings::Unknown,
                        last_transaction_id,
                    },
                )
            }
            ton_block::Account::AccountNone => nt::transport::models::RawContractState::NotExists,
        }
    };
    make_full_contract_state(account).map(JsValue::unchecked_into)
}

#[wasm_bindgen(js_name = "executeLocal")]
pub fn execute_local(
    config: &str,
    account: &str,
    message: &str,
    utime: u32,
    disable_signature_check: bool,
) -> Result<TransactionExecutorOutput, JsValue> {
    let mut account = parse_cell(account)?;
    let last_trans_lt = ton_block::Account::construct_from_cell(account.clone())
        .handle_error()?
        .last_tr_time()
        .unwrap_or_default();
    let message = ton_block::Message::construct_from_base64(message).handle_error()?;
    let config = ton_block::ConfigParams::construct_from_base64(config).handle_error()?;
    let config = ton_executor::BlockchainConfig::with_config(config).handle_error()?;

    let mut executor = ton_executor::OrdinaryTransactionExecutor::new(config);
    executor.set_signature_check_disabled(disable_signature_check);

    let params = ton_executor::ExecuteParams {
        block_unixtime: utime,
        block_lt: last_trans_lt + 10,
        last_tr_lt: Arc::new(AtomicU64::new(last_trans_lt)),
        ..Default::default()
    };

    let tx = match executor.execute_with_libs_and_params(Some(&message), &mut account, params) {
        Ok(tx) => {
            let hash = tx.hash().handle_error()?;
            nt::core::models::Transaction::try_from((hash, tx)).handle_error()?
        }
        Err(e) => {
            return match e.downcast_ref::<ton_executor::ExecutorError>() {
                Some(ton_executor::ExecutorError::NoAcceptError(code, _)) => {
                    Ok(ObjectBuilder::new()
                        .set("exitCode", *code)
                        .build()
                        .unchecked_into())
                }
                _ => Err(e).handle_error(),
            }
        }
    };

    Ok(ObjectBuilder::new()
        .set(
            "account",
            ton_types::serialize_toc(&account)
                .map(base64::encode)
                .handle_error()?,
        )
        .set("transaction", make_transaction(tx))
        .build()
        .unchecked_into())
}

#[wasm_bindgen(js_name = "getExpectedAddress")]
pub fn get_expected_address(
    tvc: &str,
    contract_abi: &str,
    workchain_id: i8,
    public_key: Option<String>,
    init_data: TokensObject,
) -> Result<ExpectedAddress, JsValue> {
    let mut state_init = ton_block::StateInit::construct_from_base64(tvc).handle_error()?;
    let contract_abi = parse_contract_abi(contract_abi)?;
    let public_key = public_key.as_deref().map(parse_public_key).transpose()?;

    state_init.data = if let Some(data) = state_init.data.take() {
        Some(insert_init_data(contract_abi, data.into(), &public_key, init_data)?.into_cell())
    } else {
        None
    };

    let cell = state_init.serialize().handle_error()?;
    let repr_hash = cell.repr_hash().to_hex_string();

    Ok(ObjectBuilder::new()
        .set(
            "stateInit",
            ton_types::serialize_toc(&cell)
                .map(base64::encode)
                .handle_error()?,
        )
        .set("address", format!("{workchain_id}:{repr_hash}"))
        .build()
        .unchecked_into())
}

#[wasm_bindgen(js_name = "getBocHash")]
pub fn get_boc_hash(boc: &str) -> Result<String, JsValue> {
    Ok(parse_cell(boc)?.repr_hash().to_hex_string())
}

#[wasm_bindgen(js_name = "packIntoCell")]
pub fn pack_into_cell(
    params: ParamsList,
    tokens: TokensObject,
    abi_version: Option<String>,
) -> Result<String, JsValue> {
    let params = parse_params_list(params).handle_error()?;
    let tokens = parse_tokens_object(&params, tokens).handle_error()?;

    let abi_version = parse_optional_abi_version(abi_version)?;
    let cell = nt::abi::pack_into_cell(&tokens, abi_version).handle_error()?;
    let bytes = ton_types::serialize_toc(&cell).handle_error()?;
    Ok(base64::encode(bytes))
}

#[wasm_bindgen(js_name = "unpackFromCell")]
pub fn unpack_from_cell(
    params: ParamsList,
    boc: &str,
    allow_partial: bool,
    abi_version: Option<String>,
) -> Result<TokensObject, JsValue> {
    let params = parse_params_list(params).handle_error()?;
    let cell = parse_cell_slice(boc)?;
    let abi_version = parse_optional_abi_version(abi_version)?;

    nt::abi::unpack_from_cell(&params, cell, allow_partial, abi_version)
        .handle_error()
        .and_then(make_tokens_object)
}

#[wasm_bindgen(js_name = "extractContractData")]
pub fn extract_contract_data(boc: &str) -> Result<Option<String>, JsValue> {
    let account_stuff = parse_account_stuff(boc)?;

    let data = match account_stuff.storage.state {
        ton_block::AccountState::AccountActive { state_init } => state_init.data,
        _ => None,
    };

    match data {
        Some(data) => {
            let data = ton_types::serialize_toc(&data).handle_error()?;
            Ok(Some(base64::encode(data)))
        }
        None => Ok(None),
    }
}

#[wasm_bindgen(js_name = "walletPrepareDeployHighloadV2")]
pub fn wallet_prepare_deploy_highload_v2(
    clock: &ClockWithOffset,
    public_key: &str,
    workchain: i8,
    timeout: u32,
) -> Result<UnsignedMessage, JsValue> {

    use nt::core::ton_wallet;

    let clock = clock.inner.as_ref();
    let public_key = parse_public_key(public_key)?;
    let expiration = nt::core::models::Expiration::Timeout(timeout);

    let inner = ton_wallet::highload_wallet_v2::prepare_deploy(
        clock,
        &public_key,
        workchain,
        expiration,
    ).handle_error()?;

    Ok(UnsignedMessage { inner })
}

#[wasm_bindgen(js_name = "extractPublicKey")]
pub fn extract_public_key(boc: &str) -> Result<String, JsValue> {
    use nt::core::ton_wallet::{highload_wallet_v2, wallet_v3};

    let account_stuff = parse_account_stuff(boc)?;

    let state_init = match &account_stuff.storage.state {
        ton_block::AccountState::AccountActive { state_init, .. } => state_init,
        _ => return Err(nt::abi::ExtractionError::AccountIsNotActive).handle_error(),
    };
    let data = match &state_init.data {
        Some(data) => data,
        None => return Err(nt::abi::ExtractionError::AccountDataNotFound).handle_error(),
    };

    if let Some(code) = &state_init.code {
        let code_hash = code.repr_hash();
        if wallet_v3::is_wallet_v3(&code_hash) {
            return wallet_v3::InitData::try_from(data)
                .handle_error()
                .and_then(|init_data| {
                    ed25519_dalek::PublicKey::from_bytes(init_data.public_key.as_slice())
                        .map(hex::encode)
                        .handle_error()
                });
        } else if highload_wallet_v2::is_highload_wallet_v2(&code_hash) {
            return highload_wallet_v2::InitData::try_from(data)
                .handle_error()
                .and_then(|init_data| {
                    ed25519_dalek::PublicKey::from_bytes(init_data.public_key.as_slice())
                        .map(hex::encode)
                        .handle_error()
                });
        }
    }

    let data = ton_types::SliceData::from(data)
        .get_next_bytes(32)
        .map_err(|_| nt::abi::ExtractionError::CellUnderflow)
        .handle_error()?;

    ed25519_dalek::PublicKey::from_bytes(&data)
        .map(hex::encode)
        .map_err(|_| nt::abi::ExtractionError::InvalidPublicKey)
        .handle_error()
}

#[wasm_bindgen(js_name = "codeToTvc")]
pub fn code_to_tvc(code: &str) -> Result<String, JsValue> {
    let cell = parse_cell(code)?;
    nt::abi::code_to_tvc(cell)
        .and_then(|x| x.serialize())
        .and_then(|x| ton_types::serialize_toc(&x))
        .map(base64::encode)
        .handle_error()
}

#[wasm_bindgen(js_name = "mergeTvc")]
pub fn merge_tvc(code: &str, data: &str) -> Result<String, JsValue> {
    let state_init = ton_block::StateInit {
        code: Some(parse_cell(code)?),
        data: Some(parse_cell(data)?),
        ..Default::default()
    };

    let cell = state_init.serialize().handle_error()?;
    let bytes = ton_types::serialize_toc(&cell).handle_error()?;
    Ok(base64::encode(bytes))
}

#[wasm_bindgen(js_name = "splitTvc")]
pub fn split_tvc(tvc: &str) -> Result<StateInit, JsValue> {
    let state_init = ton_block::StateInit::construct_from_base64(tvc).handle_error()?;

    let data = match state_init.data {
        Some(data) => {
            let data = ton_types::serialize_toc(&data).handle_error()?;
            Some(base64::encode(data))
        }
        None => None,
    };

    let code = match state_init.code {
        Some(code) => {
            let code = ton_types::serialize_toc(&code).handle_error()?;
            Some(base64::encode(code))
        }
        None => None,
    };

    Ok(ObjectBuilder::new()
        .set("data", data)
        .set("code", code)
        .build()
        .unchecked_into())
}

#[wasm_bindgen(js_name = "setCodeSalt")]
pub fn set_code_salt(code: &str, salt: &str) -> Result<String, JsValue> {
    nt::abi::set_code_salt(parse_cell(code)?, parse_cell(salt)?)
        .and_then(|cell| ton_types::serialize_toc(&cell))
        .map(base64::encode)
        .handle_error()
}

#[wasm_bindgen(js_name = "getCodeSalt")]
pub fn get_code_salt(code: &str) -> Result<Option<String>, JsValue> {
    match nt::abi::get_code_salt(parse_cell(code)?).handle_error()? {
        Some(salt) => Ok(Some(base64::encode(
            ton_types::serialize_toc(&salt).handle_error()?,
        ))),
        None => Ok(None),
    }
}

#[wasm_bindgen(js_name = "encodeInternalInput")]
pub fn encode_internal_input(
    contract_abi: &str,
    method: &str,
    input: TokensObject,
) -> Result<String, JsValue> {
    let contract_abi = parse_contract_abi(contract_abi)?;
    let method = contract_abi.function(method).handle_error()?;
    let input = parse_tokens_object(&method.inputs, input).handle_error()?;

    let body = method
        .encode_internal_input(&input)
        .and_then(|value| value.into_cell())
        .handle_error()?;
    let body = ton_types::serialize_toc(&body).handle_error()?;
    Ok(base64::encode(body))
}

#[wasm_bindgen(js_name = "encodeInternalMessage")]
pub fn encode_internal_message(
    src: Option<String>,
    dst: &str,
    bounce: bool,
    state_init: Option<String>,
    body: Option<String>,
    amount: &str,
) -> Result<String, JsValue> {
    let src = match src {
        Some(src) => ton_block::MsgAddressIntOrNone::Some(parse_address(&src)?),
        None => ton_block::MsgAddressIntOrNone::None,
    };

    let dst = parse_address(dst)?;

    let amount = u64::from_str(amount)
        .map_err(|_| "Invalid amount")
        .handle_error()?;

    let mut message = ton_block::Message::with_int_header(ton_block::InternalMessageHeader {
        ihr_disabled: true,
        bounce,
        src,
        dst,
        value: amount.into(),
        ..Default::default()
    });

    if let Some(state_init) = state_init {
        message.set_state_init(parse_state_init(&state_init)?);
    }
    if let Some(body) = body {
        message.set_body(parse_cell_slice(&body)?);
    }

    message
        .serialize()
        .and_then(|cell| ton_types::serialize_toc(&cell))
        .map(base64::encode)
        .handle_error()
}

#[wasm_bindgen(js_name = "decodeInput")]
pub fn decode_input(
    message_body: &str,
    contract_abi: &str,
    method: MethodName,
    internal: bool,
) -> Result<Option<DecodedInput>, JsValue> {
    let contract = parse_contract_abi(contract_abi)?;
    let message_body = parse_cell_slice(message_body)?;
    let method = parse_method_name(method)?;
    let (method, data) =
        match nt::abi::decode_input(&contract, message_body, &method, internal).handle_error()? {
            Some(method) => method,
            None => return Ok(None),
        };

    Ok(Some(
        ObjectBuilder::new()
            .set("method", &method.name)
            .set("input", make_tokens_object(data)?)
            .build()
            .unchecked_into(),
    ))
}

#[wasm_bindgen(js_name = "decodeEvent")]
pub fn decode_event(
    message_body: &str,
    contract_abi: &str,
    event: MethodName,
) -> Result<Option<DecodedEvent>, JsValue> {
    let contract = parse_contract_abi(contract_abi)?;
    let message_body = parse_cell_slice(message_body)?;
    let name = parse_method_name(event)?;
    let (event, data) =
        match nt::abi::decode_event(&contract, message_body, &name).handle_error()? {
            Some(event) => event,
            None => return Ok(None),
        };

    Ok(Some(
        ObjectBuilder::new()
            .set("event", &event.name)
            .set("data", make_tokens_object(data)?)
            .build()
            .unchecked_into(),
    ))
}

#[wasm_bindgen(js_name = "decodeOutput")]
pub fn decode_output(
    message_body: &str,
    contract_abi: &str,
    method: MethodName,
) -> Result<Option<DecodedOutput>, JsValue> {
    let contract = parse_contract_abi(contract_abi)?;
    let message_body = parse_cell_slice(message_body)?;
    let method = parse_method_name(method)?;
    let (method, data) =
        match nt::abi::decode_output(&contract, message_body, &method).handle_error()? {
            Some(method) => method,
            None => return Ok(None),
        };

    Ok(Some(
        ObjectBuilder::new()
            .set("method", &method.name)
            .set("output", make_tokens_object(data)?)
            .build()
            .unchecked_into(),
    ))
}

#[wasm_bindgen(js_name = "decodeTransaction")]
pub fn decode_transaction(
    transaction: Transaction,
    contract_abi: &str,
    method: MethodName,
) -> Result<Option<DecodedTransaction>, JsValue> {
    let transaction: JsValue = transaction.unchecked_into();
    if !transaction.is_object() {
        return Err(TokensJsonError::ObjectExpected).handle_error();
    }

    let contract_abi = parse_contract_abi(contract_abi)?;
    let method = parse_method_name(method)?;

    let in_msg = js_sys::Reflect::get(&transaction, &JsValue::from_str("inMessage"))?;
    if !in_msg.is_object() {
        return Err(TokensJsonError::MessageExpected).handle_error();
    }
    let internal = js_sys::Reflect::get(&in_msg, &JsValue::from_str("src"))?.is_string();

    let body_key = JsValue::from_str("body");
    let in_msg_body = match js_sys::Reflect::get(&in_msg, &body_key)?.as_string() {
        Some(body) => parse_cell_slice(&body)?,
        None => return Ok(None),
    };

    let method =
        match nt::abi::guess_method_by_input(&contract_abi, &in_msg_body, &method, internal)
            .handle_error()?
        {
            Some(method) => method,
            None => return Ok(None),
        };

    let input = method.decode_input(in_msg_body, internal).handle_error()?;

    let out_msgs = js_sys::Reflect::get(&transaction, &JsValue::from_str("outMessages"))?;
    if !js_sys::Array::is_array(&out_msgs) {
        return Err(TokensJsonError::ArrayExpected).handle_error();
    }

    let dst_key = JsValue::from_str("dst");
    let ext_out_msgs = out_msgs
        .unchecked_into::<js_sys::Array>()
        .iter()
        .filter_map(|message| {
            match js_sys::Reflect::get(&message, &dst_key) {
                Ok(dst) if dst.is_string() => return None,
                Err(error) => return Some(Err(error)),
                _ => {}
            };

            Some(
                match js_sys::Reflect::get(&message, &body_key).map(|item| item.as_string()) {
                    Ok(Some(body)) => parse_cell_slice(&body),
                    Ok(None) => Err(TokensJsonError::MessageBodyExpected).handle_error(),
                    Err(error) => Err(error),
                },
            )
        })
        .collect::<Result<Vec<_>, JsValue>>()?;

    let output = nt::abi::process_raw_outputs(&ext_out_msgs, method).handle_error()?;

    Ok(Some(
        ObjectBuilder::new()
            .set("method", &method.name)
            .set("input", make_tokens_object(input)?)
            .set("output", make_tokens_object(output)?)
            .build()
            .unchecked_into(),
    ))
}

#[wasm_bindgen(js_name = "decodeTransactionEvents")]
pub fn decode_transaction_events(
    transaction: Transaction,
    contract_abi: &str,
) -> Result<DecodedTransactionEvents, JsValue> {
    let transaction: JsValue = transaction.unchecked_into();
    if !transaction.is_object() {
        return Err(TokensJsonError::ObjectExpected).handle_error();
    }

    let contract_abi = parse_contract_abi(contract_abi)?;

    let out_msgs = js_sys::Reflect::get(&transaction, &JsValue::from_str("outMessages"))?;
    if !js_sys::Array::is_array(&out_msgs) {
        return Err(TokensJsonError::ArrayExpected).handle_error();
    }

    let body_key = JsValue::from_str("body");
    let dst_key = JsValue::from_str("dst");
    let ext_out_msgs = out_msgs
        .unchecked_into::<js_sys::Array>()
        .iter()
        .filter_map(|message| {
            match js_sys::Reflect::get(&message, &dst_key) {
                Ok(dst) if dst.is_string() => return None,
                Err(error) => return Some(Err(error)),
                _ => {}
            };

            Some(
                match js_sys::Reflect::get(&message, &body_key).map(|item| item.as_string()) {
                    Ok(Some(body)) => parse_cell_slice(&body),
                    Ok(None) => return None,
                    Err(error) => Err(error),
                },
            )
        })
        .collect::<Result<Vec<_>, JsValue>>()?;

    let events = ext_out_msgs
        .into_iter()
        .filter_map(|body| {
            let id = nt::abi::read_function_id(&body).ok()?;
            let event = contract_abi.event_by_id(id).ok()?;
            let tokens = event.decode_input(body).ok()?;

            let data = match make_tokens_object(tokens) {
                Ok(data) => data,
                Err(e) => return Some(Err(e)),
            };

            Some(Ok(ObjectBuilder::new()
                .set("event", &event.name)
                .set("data", data)
                .build()))
        })
        .collect::<Result<js_sys::Array, JsValue>>()?;

    Ok(events.unchecked_into())
}

#[wasm_bindgen(js_name = "getDataHash")]
pub fn get_hash(data: &str) -> Result<String, JsValue> {
    use sha2::Digest;

    let body = parse_base64_or_hex_bytes(data).handle_error()?;
    Ok(hex::encode(sha2::Sha256::digest(&body)))
}

#[wasm_bindgen(js_name = "ed25519_generateKeyPair")]
pub fn generate_ed25519_key_pair() -> Result<Ed25519KeyPair, JsValue> {
    let key_pair = ed25519_dalek::Keypair::generate(&mut rand::thread_rng());
    Ok(make_ed25519_key_pair(key_pair))
}

#[wasm_bindgen(js_name = "ed25519_sign")]
pub fn sign_data(
    secret_key: &str,
    data: &str,
    signature_id: Option<i32>,
) -> Result<String, JsValue> {
    let data = parse_hex_or_base64_bytes(data).handle_error()?;

    let mut secret_key = parse_hex_or_base64_bytes(secret_key).handle_error()?;
    let secret = ed25519_dalek::SecretKey::from_bytes(&secret_key).handle_error()?;
    secret_key.zeroize();

    let data = nt::crypto::extend_with_signature_id(&data, signature_id);

    let public = ed25519_dalek::PublicKey::from(&secret);
    let key_pair = ed25519_dalek::Keypair { secret, public };
    let signature = key_pair.sign(data.as_ref());
    Ok(base64::encode(signature.to_bytes()))
}

#[wasm_bindgen(js_name = "extendSignature")]
pub fn extend_signature(signature: &str) -> Result<ExtendedSignature, JsValue> {
    let signature = parse_signature(signature)?;
    Ok(make_extended_signature(signature.to_bytes()))
}

#[wasm_bindgen(js_name = "verifySignature")]
pub fn verify_signature(
    public_key: &str,
    data: &str,
    signature: &str,
    signature_id: Option<i32>,
) -> Result<bool, JsValue> {
    let public_key = parse_public_key(public_key)?;

    let data = parse_hex_or_base64_bytes(data).handle_error()?;
    let signature = parse_signature(signature)?;

    let data = nt::crypto::extend_with_signature_id(&data, signature_id);

    Ok(public_key.verify(data.as_ref(), &signature).is_ok())
}

#[wasm_bindgen(js_name = "createRawExternalMessage")]
pub fn create_raw_external_message(
    dst: &str,
    state_init: Option<String>,
    body: Option<String>,
    expire_at: u32,
) -> Result<SignedMessage, JsValue> {
    // Parse params
    let dst = parse_address(dst)?;

    // Build message
    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst,
            ..Default::default()
        });

    if let Some(state_init) = state_init {
        message.set_state_init(parse_state_init(&state_init)?);
    }
    if let Some(body) = body {
        message.set_body(parse_cell_slice(&body)?);
    }

    // Serialize message
    make_signed_message(nt::crypto::SignedMessage { message, expire_at })
}

#[wasm_bindgen(js_name = "createExternalMessageWithoutSignature")]
pub fn create_external_message_without_signature(
    clock: &ClockWithOffset,
    dst: &str,
    contract_abi: &str,
    method: &str,
    state_init: Option<String>,
    input: TokensObject,
    timeout: u32,
) -> Result<SignedMessage, JsValue> {
    use nt::core::models::{Expiration, ExpireAt};

    // Parse params
    let dst = parse_address(dst)?;
    let contract_abi = parse_contract_abi(contract_abi)?;
    let method = contract_abi.function(method).handle_error()?;
    let input = parse_tokens_object(&method.inputs, input).handle_error()?;

    // Prepare headers
    let time = clock.inner.now_ms_u64();
    let expire_at = ExpireAt::new_from_millis(Expiration::Timeout(timeout), time);

    let mut header = HashMap::with_capacity(3);
    header.insert("time".to_string(), ton_abi::TokenValue::Time(time));
    header.insert(
        "expire".to_string(),
        ton_abi::TokenValue::Expire(expire_at.timestamp),
    );
    header.insert("pubkey".to_string(), ton_abi::TokenValue::PublicKey(None));

    // Encode body
    let body = method
        .encode_input(&header, &input, false, None, Some(dst.clone()))
        .handle_error()?;

    // Build message
    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst,
            ..Default::default()
        });
    if let Some(state_init) = state_init {
        message.set_state_init(parse_state_init(&state_init)?);
    }
    message.set_body(body.into());

    // Serialize message
    make_signed_message(nt::crypto::SignedMessage {
        message,
        expire_at: expire_at.timestamp,
    })
}

#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = "createExternalMessage")]
pub fn create_external_message(
    clock: &ClockWithOffset,
    dst: &str,
    contract_abi: &str,
    method: &str,
    state_init: Option<String>,
    input: TokensObject,
    public_key: &str,
    timeout: u32,
) -> Result<UnsignedMessage, JsValue> {
    let dst = parse_address(dst)?;
    let contract_abi = parse_contract_abi(contract_abi)?;
    let method = contract_abi.function(method).handle_error()?;
    let input = parse_tokens_object(&method.inputs, input).handle_error()?;
    let public_key = parse_public_key(public_key)?;

    let mut message =
        ton_block::Message::with_ext_in_header(ton_block::ExternalInboundMessageHeader {
            dst,
            ..Default::default()
        });
    if let Some(state_init) = state_init {
        message.set_state_init(parse_state_init(&state_init)?);
    }

    Ok(UnsignedMessage {
        inner: nt::core::utils::make_labs_unsigned_message(
            clock.inner.as_ref(),
            message,
            nt::core::models::Expiration::Timeout(timeout),
            &public_key,
            Cow::Owned(method.clone()),
            input,
        )
        .handle_error()?,
    })
}
