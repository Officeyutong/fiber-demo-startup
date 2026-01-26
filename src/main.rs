use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{CellOutput, JsonBytes, OutPoint, Script, ScriptHashType};
use ckb_sdk::constants::SIGHASH_TYPE_HASH;
use ckb_sdk::rpc::ckb_indexer::{Order, SearchKey, SearchKeyFilter};
use ckb_sdk::traits::{DefaultTransactionDependencyProvider, SecpCkbRawKeySigner};
use ckb_sdk::tx_builder::unlock_tx;
use ckb_sdk::unlock::{ScriptUnlocker, SecpSighashUnlocker};
use ckb_sdk::{CkbRpcClient, ScriptId};
use ckb_types::core::TransactionView;
use ckb_types::packed::{Byte, CellInput, CellOutputBuilder, Script as PackedScript, WitnessArgs};
use ckb_types::prelude::*;
use ckb_types::{H256, h256};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;
use std::str::FromStr;

const CKB_RPC_URL: &str = "http://127.0.0.1:8114";
const PRIVATE_KEY: &str = "63d86723e08f0f813a36ce6aa123bb2289d90680ae1e99d4de8cdb334553f24d";

const SUDT_CODE_HASH: H256 =
    h256!("0xe1e354d6d643ad42724d40967e334984534e0367405c5ae42a9d7d63d77df419");
const SUDT_ARGS: &str = "c219351b150b900e50a7039f1e448b844110927e5fd9bd30425806cb8ddff1fd";

#[derive(Debug)]
pub struct LiveCell {
    pub out_point: OutPoint,
    pub output: CellOutput,
    pub output_data: JsonBytes,
}

fn get_lock_script_from_private_key(private_key_hex: &str) -> Script {
    let secp = Secp256k1::new();
    let private_key_bytes = hex::decode(private_key_hex).expect("Invalid hex string");
    let secret_key = SecretKey::from_slice(&private_key_bytes).expect("Invalid private key");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    let pubkey_bytes = public_key.serialize();
    let pubkey_hash = blake2b_256(&pubkey_bytes);
    let pubkey_hash160: [u8; 20] = pubkey_hash[0..20].try_into().unwrap();

    Script {
        code_hash: SIGHASH_TYPE_HASH.clone(),
        hash_type: ScriptHashType::Type,
        args: JsonBytes::from_vec(pubkey_hash160.to_vec()),
    }
}

fn list_live_cells(client: &CkbRpcClient, private_key_hex: &str) -> Vec<LiveCell> {
    let lock_script = Script {
        code_hash: SIGHASH_TYPE_HASH.clone(),
        hash_type: ScriptHashType::Type,
        args: {
            let secp = Secp256k1::new();
            let secret_key = SecretKey::from_str(private_key_hex).unwrap();
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            let pubkey_hash_160: [u8; 20] = blake2b_256(&public_key.serialize())[0..20]
                .try_into()
                .unwrap();

            JsonBytes::from_vec(pubkey_hash_160.to_vec())
        },
    };

    println!("Lock script: {:?}", lock_script);

    let search_key = SearchKey {
        script: lock_script,
        script_type: ckb_sdk::rpc::ckb_indexer::ScriptType::Lock,
        script_search_mode: Some(ckb_sdk::rpc::ckb_indexer::SearchMode::Exact),
        filter: None,
        with_data: Some(true),
        group_by_transaction: Some(false),
    };

    let mut live_cells = Vec::new();
    let mut cursor = None;

    loop {
        let cells = client
            .get_cells(
                search_key.clone(),
                Order::Asc,
                100u32.into(),
                cursor.clone(),
            )
            .expect("Failed to get cells");

        if cells.objects.is_empty() {
            break;
        }

        for cell in cells.objects {
            live_cells.push(LiveCell {
                out_point: cell.out_point,
                output: cell.output,
                output_data: cell.output_data.unwrap_or_default(),
            });
        }

        cursor = Some(cells.last_cursor);
    }

    live_cells
}

/// Get sUDT type script
fn get_sudt_type_script() -> Script {
    Script {
        code_hash: SUDT_CODE_HASH.clone(),
        hash_type: ScriptHashType::Data,
        args: JsonBytes::from_vec(hex::decode(SUDT_ARGS).unwrap()),
    }
}

/// Find sUDT cells owned by the given private key
fn find_sudt_cells(client: &CkbRpcClient, private_key_hex: &str) -> Vec<LiveCell> {
    let lock_script = get_lock_script_from_private_key(private_key_hex);
    let sudt_type_script = get_sudt_type_script();

    let search_key = SearchKey {
        script: lock_script.clone(),
        script_type: ckb_sdk::rpc::ckb_indexer::ScriptType::Lock,
        script_search_mode: None,
        filter: Some(SearchKeyFilter {
            script: Some(sudt_type_script),
            script_len_range: None,
            output_data: None,
            output_data_filter_mode: None,
            output_data_len_range: None,
            output_capacity_range: None,
            block_range: None,
        }),
        with_data: Some(true),
        group_by_transaction: None,
    };

    let mut sudt_cells = Vec::new();
    let mut cursor = None;

    loop {
        let cells = client
            .get_cells(
                search_key.clone(),
                Order::Asc,
                100u32.into(),
                cursor.clone(),
            )
            .expect("Failed to get cells");

        if cells.objects.is_empty() {
            break;
        }

        for cell in cells.objects {
            sudt_cells.push(LiveCell {
                out_point: cell.out_point,
                output: cell.output,
                output_data: cell.output_data.unwrap_or_default(),
            });
        }

        cursor = Some(cells.last_cursor);
    }

    sudt_cells
}

/// Parse sUDT amount from cell data (little-endian u128)
fn parse_sudt_amount(data: &[u8]) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[0..16]);
    u128::from_le_bytes(bytes)
}

/// Encode amount as sUDT cell data (little-endian u128)
fn encode_sudt_amount(amount: u128) -> Vec<u8> {
    amount.to_le_bytes().to_vec()
}

/// Burn one unit of sUDT
fn burn_one_sudt(client: &CkbRpcClient, private_key_hex: &str) -> H256 {
    let sudt_cells = find_sudt_cells(client, private_key_hex);
    assert!(!sudt_cells.is_empty(), "No sUDT cells found");

    let sudt_cell = &sudt_cells[0];
    let current_amount = parse_sudt_amount(sudt_cell.output_data.as_bytes());
    assert!(current_amount >= 1, "sUDT amount is 0, cannot burn");

    let new_amount = current_amount - 1;
    println!("Burning 1 sUDT: {} -> {}", current_amount, new_amount);

    let lock_script = get_lock_script_from_private_key(private_key_hex);
    let sudt_type_script = get_sudt_type_script();

    // Build input
    let input = CellInput::new_builder()
        .previous_output(
            ckb_types::packed::OutPoint::new_builder()
                .tx_hash(sudt_cell.out_point.tx_hash.0.pack())
                .index(sudt_cell.out_point.index.value() as u32)
                .build(),
        )
        .build();

    // Build output, deduct transaction fee
    const TX_FEE: u64 = 1000; // 1000 shannons
    let capacity: ckb_types::core::Capacity =
        ckb_types::core::Capacity::shannons(u64::from(sudt_cell.output.capacity) - TX_FEE);

    let output = CellOutputBuilder::default()
        .capacity(capacity.pack())
        .lock(
            PackedScript::new_builder()
                .code_hash(lock_script.code_hash.0.pack())
                .hash_type(Byte::new(lock_script.hash_type as u8))
                .args(lock_script.args.as_bytes().pack())
                .build(),
        )
        .type_(
            Some(
                PackedScript::new_builder()
                    .code_hash(sudt_type_script.code_hash.0.pack())
                    .hash_type(Byte::new(sudt_type_script.hash_type as u8))
                    .args(sudt_type_script.args.as_bytes().pack())
                    .build(),
            )
            .pack(),
        )
        .build();

    let output_data = encode_sudt_amount(new_amount);

    // Build transaction
    let tx = TransactionView::new_advanced_builder()
        .input(input)
        .output(output)
        .output_data(output_data.pack())
        .cell_dep(
            ckb_types::packed::CellDep::new_builder()
                .out_point(get_secp256k1_cell_dep(client))
                .dep_type(Byte::new(ckb_types::core::DepType::DepGroup as u8))
                .build(),
        )
        .cell_dep(
            ckb_types::packed::CellDep::new_builder()
                .out_point(get_sudt_cell_dep(client))
                .dep_type(Byte::new(ckb_types::core::DepType::Code as u8))
                .build(),
        )
        .witness(WitnessArgs::default().as_bytes().pack())
        .build();

    // Sign transaction
    let tx = sign_transaction(tx, private_key_hex);

    // Send transaction
    let tx_hash = client
        .send_transaction(tx.data().into(), None)
        .expect("Failed to send transaction");

    println!("Transaction sent: {:#x}", tx_hash);
    tx_hash
}

/// Get secp256k1 cell dep (from genesis block)
fn get_secp256k1_cell_dep(client: &CkbRpcClient) -> ckb_types::packed::OutPoint {
    let genesis = client.get_block_by_number(0u64.into()).unwrap().unwrap();
    let tx_hash = genesis.transactions[1].hash.clone();
    ckb_types::packed::OutPoint::new_builder()
        .tx_hash(tx_hash.0.pack())
        .index(0u32)
        .build()
}

/// Get sUDT cell dep
fn get_sudt_cell_dep(client: &CkbRpcClient) -> ckb_types::packed::OutPoint {
    // In fiber devnet, sUDT (simple_udt) is deployed in genesis block cellbase
    // output 0 is genesis_cell, system_cells start from output 1
    // simple_udt is the 8th system_cell, so index = 1 + 7 = 8
    let genesis = client.get_block_by_number(0u64.into()).unwrap().unwrap();
    let tx_hash = genesis.transactions[0].hash.clone();
    ckb_types::packed::OutPoint::new_builder()
        .tx_hash(tx_hash.0.pack())
        .index(8u32)
        .build()
}

/// Sign transaction
fn sign_transaction(tx: TransactionView, private_key_hex: &str) -> TransactionView {
    let private_key_bytes = hex::decode(private_key_hex).unwrap();
    let secret_key = secp256k1::SecretKey::from_slice(&private_key_bytes).unwrap();

    let tx_dep_provider = DefaultTransactionDependencyProvider::new(CKB_RPC_URL, 10);

    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![secret_key]);
    let script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);

    let mut unlockers: HashMap<ScriptId, Box<dyn ScriptUnlocker>> = HashMap::new();
    unlockers.insert(script_id, Box::new(unlocker));

    let (signed_tx, _) = unlock_tx(tx, &tx_dep_provider, &unlockers).unwrap();
    signed_tx
}

/// Calculate lock script hash (for sUDT args, must be 32 bytes)
fn calc_lock_script_hash(private_key_hex: &str) -> [u8; 32] {
    let lock_script = get_lock_script_from_private_key(private_key_hex);

    // Build packed script
    let packed_script = PackedScript::new_builder()
        .code_hash(lock_script.code_hash.0.pack())
        .hash_type(Byte::new(1)) // Type = 1
        .args(lock_script.args.as_bytes().pack())
        .build();

    // Calculate hash
    let hash = packed_script.calc_script_hash();
    hash.as_slice().try_into().unwrap()
}

fn main() {
    let client = CkbRpcClient::new(CKB_RPC_URL);

    // Print correct lock script hash (for sUDT type.args in dev.toml)
    let lock_hash = calc_lock_script_hash(PRIVATE_KEY);
    println!("=== Lock script hash for sUDT type.args (32 bytes) ===");
    println!("0x{}", hex::encode(lock_hash));
    println!("=======================================================\n");

    println!("{:#?}", list_live_cells(&client, PRIVATE_KEY));
    // List sUDT cells
    let sudt_cells = find_sudt_cells(&client, PRIVATE_KEY);
    println!("Found {} sUDT cells:", sudt_cells.len());
    for (i, cell) in sudt_cells.iter().enumerate() {
        let amount = parse_sudt_amount(cell.output_data.as_bytes());
        println!(
            "sUDT Cell {}: tx_hash={}, index={}, amount={}",
            i, cell.out_point.tx_hash, cell.out_point.index, amount
        );
    }

    // Burn one unit of sUDT
    if !sudt_cells.is_empty() {
        let tx_hash = burn_one_sudt(&client, PRIVATE_KEY);
        println!("Burn transaction hash: {:#x}", tx_hash);
    }
}
