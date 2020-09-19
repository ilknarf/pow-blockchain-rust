extern crate crypto; // aka rust-crypto

use std::io::{Cursor, Write};
use std::fmt::{Display, Formatter, Result};
use std::str;
use std::boxed::Box;
use std::option::Option;
use self::crypto::digest::Digest;
use self::crypto::sha3::Sha3;
use hex::encode;
use byteorder::{LittleEndian, ReadBytesExt};

const TARGET: u32 = 5; // target number zeroes

// 14 byte - number || 64 byte - last block hash || 64-byte - merkle root || 20 byte - data || 18 byte - nonce || total 180 bytes
// merkle root = sha3(block + last_merkle_root)

const GENESIS_BLOCK: Block = Block{
    number: [0u8; 14],
    last_block_hash: [0u8; 64],
    merkle_root: [0u8; 64],
    data: [0u8; 20],
    nonce: [0u8; 18],
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
            data: [0u8; 20],
            last_block: Option::from(Box::new(last_block)),
            nonce: [0u8; 18],
        };

        println!("{}", last_block);
    }
}

type Link = Option<Box<Block>>;

struct Block{
    number: [u8; 14], // len 14
    last_block_hash: [u8; 64], // len 64
    merkle_root: [u8; 64], // len 64
    data: [u8; 20], // len 20
    nonce: [u8; 18], // len 18
    last_block: Link,
}

impl Block {
    fn hash(&self) -> [u8; 64] {
        let mut sha3 = Sha3::keccak256();

        sha3.input(&self.number);
        sha3.input(&self.last_block_hash);
        sha3.input(&self.merkle_root);
        sha3.input(&self.data);
        sha3.input(&self.nonce);

        let mut result = [0u8; 64];
        sha3.result(&mut result);
        result
    }

    fn next_number(&self) -> [u8; 14] {
        let mut v = vec![0, 0];
        v.extend(&self.number);

        let mut cur = Cursor::new(v);
        let next_num = cur.read_u128::<LittleEndian>().unwrap();

        let mut res = [0u8; 14];
        for (i, number) in next_num.to_le_bytes()[2..].iter().enumerate() {
            res[i] = *number;
        }

        res
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let data_string = match str::from_utf8(&self.data) {
            Ok(s) => s,
            Err(_) => "Decoding error",
        };


        f.write_fmt(format_args!(
            "number: {}, last_block: {}{}, merkle_root: {}{}, data: {}",
            encode(&self.number),
            encode(&self.last_block_hash[..32]),
            encode(&self.last_block_hash[32..]),
            encode(&self.merkle_root[..32]),
            encode(&self.merkle_root[32..]),
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

