extern crate crypto; // aka rust-crypto

use std::io::{Cursor, Write};
use std::fmt::{Display, Formatter, Result};
use std::str;
use std::u128;
use std::boxed::Box;
use std::option::Option;
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use hex::encode;

const TARGET: u32 = 6; // target number zeroes

// 14 byte - number || 64 byte - last block hash || 64-byte - merkle root || 22 byte - data || 16 byte - nonce || total 180 bytes
// merkle root = sha3(block + last_merkle_root)

const GENESIS_BLOCK: Block = Block{
    number: [0u8; 14],
    last_block_hash: [0u8; 64],
    merkle_root: [0u8; 64],
    data: [0u8; 22],
    nonce: [0u8; 16],
    last_block: None,
};

fn main() {
    let mut last_block = GENESIS_BLOCK;

    loop {
        let mut last_block_hash= last_block.hash();
        let &last_merkle_root = &last_block.merkle_root;

        let merkle_root = calculate_merkle_root(&last_block_hash, &last_merkle_root);

        last_block = Block{
            number: last_block.next_number(),
            last_block_hash,
            merkle_root,
            data: [0u8; 22],
            last_block: Option::from(Box::new(last_block)),
            nonce: [0u8; 16],
        };

        println!("{}", last_block);
    }
}

type Link = Option<Box<Block>>;

struct Block{
    number: [u8; 14], // len 14
    last_block_hash: [u8; 64], // len 64
    merkle_root: [u8; 64], // len 64
    data: [u8; 22], // len 22
    nonce: u128, // len 16
    last_block: Link,
}

impl Block {
    fn hash(&self) -> [u8; 64] {
        let mut sha3 = Sha3::keccak256();

        sha3.input(&self.number);
        sha3.input(&self.last_block_hash);
        sha3.input(&self.merkle_root);
        sha3.input(&self.data);
        sha3.input(&self.nonce.to_be_bytes());

        let mut result = [0u8; 64];
        sha3.result(&mut result);
        result
    }

    // next_number actually copies then uncopies from 16-byte arrays; unfortunately
    // requires 16-length arrays to convert
    fn next_number(&self) -> [u8; 14] {
        let mut a = [0u8; 16];

        for i in 2..14 {
            a[i] = self.number[i - 2];
        }

        let next_num = u128::from_be_bytes(a) + 1;
        println!("{:?}", next_num.to_le_bytes());

        let mut res = [0u8; 14];
        for (i, number) in next_num.to_be_bytes()[1..14].iter().enumerate() {
            res[i] = *number;
        }

        res
    }

    fn mine(&mut self) {

        for i in 0..u128::MAX {
            self.nonce = self.nonce + 1;

            if self.hash()[..TARGET].iter().all(|v| v == 0) == [] {
                return
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
            "number: {}, last_block: {}{}, merkle_root: {}{}, nonce: {}, data: {}",
            encode(&self.number),
            encode(&self.last_block_hash[..32]),
            encode(&self.last_block_hash[32..]),
            encode(&self.merkle_root[..32]),
            encode(&self.merkle_root[32..]),
            &self.nonce,
            data_string,
        ))
    }
}

fn calculate_merkle_root(block_hash: &[u8; 64], last_merkle_root: &[u8; 64]) -> [u8; 64] {
    let mut sha3 = Sha3::keccak256();

    sha3.input(block_hash);
    sha3.input(last_merkle_root);

    let mut result = [0u8; 64];
    sha3.result(&mut result);
    result
}

