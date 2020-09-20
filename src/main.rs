extern crate crypto; // aka rust-crypto

use std::fmt::{Display, Formatter, Result};
use std::str;
use std::u128;
use std::boxed::Box;
use std::option::Option;
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use hex::encode;

const TARGET: usize = 4; // target number zeroes
const ODD: bool = TARGET % 2 == 1;
const WHOLE_BYTES: usize = TARGET >> 1;

// 16 byte - number || 64 byte - last block hash || 64-byte - merkle root || 20 byte - data || 16 byte - nonce || total 180 bytes
// merkle root = sha3(block + last_merkle_root)

const GENESIS_BLOCK: Block = Block{
    number: 0,
    last_block_hash: [0u8; 32],
    merkle_root: [0u8; 32],
    data: [0u8; 20],
    nonce: 0,
    last_block: None,
};

fn main() {
    let mut last_block = GENESIS_BLOCK;

    loop {
        let last_block_hash= last_block.hash();
        let &last_merkle_root = &last_block.merkle_root;

        let merkle_root = calculate_merkle_root(&last_block_hash, &last_merkle_root);

        last_block = Block{
            number: last_block.next_number(),
            last_block_hash,
            merkle_root,
            data: [0u8; 20],
            last_block: Option::from(Box::new(last_block)),
            nonce: 0,
        };

        last_block.mine();

        println!("{}", last_block);
    }
}

type Link = Option<Box<Block>>;

struct Block{
    number: u128, // len 16
    last_block_hash: [u8; 32], // len 64
    merkle_root: [u8; 32], // len 64
    data: [u8; 20], // len 22
    nonce: u128, // len 16
    last_block: Link,
}

impl Block {
    fn hash(&self) -> [u8; 32] {
        let mut sha3 = Sha3::keccak256();

        sha3.input(&self.number.to_be_bytes());
        sha3.input(&self.last_block_hash);
        sha3.input(&self.merkle_root);
        sha3.input(&self.data);
        sha3.input(&self.nonce.to_be_bytes());

        let mut result = [0u8; 32];
        sha3.result(&mut result);
        result
    }

    // next_number actually copies then uncopies from 16-byte arrays; unfortunately
    // requires 16-length arrays to convert
    fn next_number(&self) -> u128 {
        self.number + 1
    }

    fn mine(&mut self) {
        loop {
            self.nonce += 1;

            let hash = self.hash();
            if hash[..WHOLE_BYTES].iter().all(|&v| v == 0u8) {
                if ODD {
                    if hash[WHOLE_BYTES] & 15 << 4 == 0 {
                      return
                    }
                } else{
                    return
                }
            }
        }
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let data_string = match str::from_utf8(&self.data) {
            Ok(s) => s,
            Err(_) => "Decoding error",
        };


        f.write_fmt(format_args!(
            "number: {}, last_block: {}, merkle_root: {}, nonce: {}, data: {}",
            &self.number,
            encode(&self.last_block_hash),
            encode(&self.merkle_root),
            &self.nonce,
            data_string,
        ))
    }
}

fn calculate_merkle_root(block_hash: &[u8; 32], last_merkle_root: &[u8; 32]) -> [u8; 32] {
    let mut sha3 = Sha3::keccak256();

    sha3.input(block_hash);
    sha3.input(last_merkle_root);

    let mut result = [0u8; 32];
    sha3.result(&mut result);
    result
}

