// Copyright 2017-2019 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

extern crate sgx_tstd as std;

use std::prelude::v1::String;

use codec::{Decode, Encode};
use sp_core::{
    crypto::{KeyTypeId, Pair},
    ed25519,
    hash::H256,
    offchain::{
        HttpError, HttpRequestId, HttpRequestStatus, OpaqueNetworkState, StorageKind, Timestamp,
    },
    sr25519, ecdsa
};
use std::char;
use std::println;
use sp_core::LogLevel;

use sp_runtime_interface::{runtime_interface, Pointer};


#[allow(unused)]
fn encode_hex_digit(digit: u8) -> char {
    match char::from_digit(u32::from(digit), 16) {
        Some(c) => c,
        _ => panic!(),
    }
}

#[allow(unused)]
fn encode_hex_byte(byte: u8) -> [char; 2] {
    [encode_hex_digit(byte >> 4), encode_hex_digit(byte & 0x0Fu8)]
}

#[allow(unused)]
pub fn encode_hex(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes
        .iter()
        .map(|byte| encode_hex_byte(*byte).iter().copied().collect())
        .collect();
    strs.join("")
}

use sgx_log::*;
use std::{vec, vec::Vec};

// Reexport here, such that the worker does not need to import other crate.
// Not sure if this is a good Idea though.
pub use sgx_externalities::{with_externalities, SgxExternalities, SgxExternalitiesTrait, SgxExternalitiesType};

/// Error verifying ECDSA signature
#[derive(Encode, Decode)]
pub enum EcdsaVerifyError {
    /// Incorrect value of R or S
    BadRS,
    /// Incorrect value of V
    BadV,
    /// Invalid signature
    BadSignature,
}

/// Interface for accessing the storage from within the runtime.
#[runtime_interface]
pub trait Storage {
    fn get(key: &[u8]) -> Option<Vec<u8>> {
        debug!("storage('{}')", encode_hex(key));
        with_externalities(|ext| {
            ext.get(key).map(|s| {
                debug!("  returning {}", encode_hex(s));
                s.to_vec()
            })
        })
        .expect("storage cannot be called outside of an Externalities-provided environment.")
    }

    fn read(key: &[u8], value_out: &mut [u8], value_offset: u32) -> Option<u32> {
        debug!(
            "read_storage('{}' with offset =  {:?}. value_out.len() is {})",
            encode_hex(key),
            value_offset,
            value_out.len()
        );
        with_externalities(|ext| {
            ext.get(key).map(|value| {
                debug!("  entire stored value: {:?}", value);
                let value = &value[value_offset..];
                debug!("  stored value at offset: {:?}", value);
                let written = std::cmp::min(value.len(), value_out.len());
                value_out[..written].copy_from_slice(&value[..written]);
                debug!("  write back {:?}, return len {}", value_out, value.len());
                value.len()
            })
        })
        .expect("read_storage cannot be called outside of an Externalities-provided environment.")
    }

    fn set(key: &[u8], value: &[u8]) {
        debug!("set_storage('{}', {:x?})", encode_hex(key), value);
        with_externalities(|ext| ext.insert(key.to_vec(), value.to_vec()));
    }

    fn clear(key: &[u8]) {
        with_externalities(|ext|
            if let None = ext.remove(key) {
                info!("Tried to clear storage that was not existing");
            });
    }

    fn exists(key: &[u8]) -> bool {
        with_externalities(|ext|
            ext.contains_key(key)
        ).expect("exists cannot be called outside of an Externalities-provided environment.")
    }

    fn clear_prefix(prefix: &[u8]) {
        warn!("storage::clear_prefix() unimplemented");
    }

    /// Append the encoded `value` to the storage item at `key`.
    ///
    /// The storage item needs to implement [`EncodeAppend`](codec::EncodeAppend).
    ///
    /// # Warning
    ///
    /// If the storage item does not support [`EncodeAppend`](codec::EncodeAppend) or
    /// something else fails at appending, the storage item will be set to `[value]`.
    fn append(key: &[u8], value: Vec<u8>) {
        warn!("storage::append() unimplemented");
    }

    fn root() -> [u8; 32] {
        warn!("storage::root() unimplemented");
        [0u8; 32]
    }

    fn changes_root(parent_hash: &[u8]) -> Option<[u8; 32]> {
        warn!("storage::changes_root() unimplemented");
        Some([0u8; 32])
    }

    /// Get the next key in storage after the given one in lexicographic order.
    fn next_key(key: &[u8]) -> Option<Vec<u8>> {
        warn!("storage::next_key unimplemented");
        Some([0u8; 32].to_vec())
    }

	/// Start a new nested transaction.
	///
	/// This allows to either commit or roll back all changes that are made after this call.
	/// For every transaction there must be a matching call to either `rollback_transaction`
	/// or `commit_transaction`. This is also effective for all values manipulated using the
	/// `DefaultChildStorage` API.
	///
	/// # Warning
	///
	/// This is a low level API that is potentially dangerous as it can easily result
	/// in unbalanced transactions. For example, FRAME users should use high level storage
	/// abstractions.
	fn start_transaction() {
		warn!("storage::start_transaction unimplemented");
	}

	/// Rollback the last transaction started by `start_transaction`.
	///
	/// Any changes made during that transaction are discarded.
	///
	/// # Panics
	///
	/// Will panic if there is no open transaction.
	fn rollback_transaction() {
		warn!("storage::rollback_transaction unimplemented");
	}

	/// Commit the last transaction started by `start_transaction`.
	///
	/// Any changes made during that transaction are committed.
	///
	/// # Panics
	///
	/// Will panic if there is no open transaction.
	fn commit_transaction() {
        warn!("storage::commit_transaction unimplemented");
    }
}

#[runtime_interface]
pub trait DefaultChildStorage  {
    fn read(
        storage_key: &[u8],
        key: &[u8],
        value_out: &mut [u8],
        value_offset: u32,
    ) -> Option<u32> {
        // TODO unimplemented
        warn!("default_child_storage::read() unimplemented");
        Some(0)
    }

    fn get(storage_key: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        // TODO: unimplemented
        warn!("default_child_storage::get() unimplemented");
        Some(vec![0, 1, 2, 3])
    }

    fn set(
        storage_key: &[u8],
        key: &[u8],
        value: &[u8],
    ) {
        warn!("default_child_storage::set() unimplemented");
    }

    fn clear(
        storage_key: &[u8],
        key: &[u8]
    ) {
        warn!("child storage::clear() unimplemented");
    }

    fn storage_kill(
        storage_key: &[u8],
    ) {
        warn!("child storage::storage_kill() unimplemented");
    }

    #[version(2)]
    fn storage_kill(
        storage_key: &[u8],
        limit: Option<u32>
    ) -> bool {
        warn!("child storage::storage_kill() unimplemented");
        false
    }

    fn exists(
        storage_key: &[u8],
        key: &[u8]
    ) -> bool {
        warn!("child storage::exists() unimplemented");
        false
    }

    fn clear_prefix(
        storage_key: &[u8],
        prefix: &[u8],
    ) {
        warn!("child storage::clear_prefix() unimplemented");
    }

    fn root(
        storage_key: &[u8]
    ) -> Vec<u8> {
        warn!("child storage::root() unimplemented");
        vec![0, 1, 2, 3]
    }

    fn next_key(
        storage_key: &[u8],
        key: &[u8],
    ) -> Option<Vec<u8>> {
        warn!("child storage::next_key() unimplemented");
        Some(Vec::new())
    }
}


#[runtime_interface]
pub trait Trie {
    /// A trie root formed from the iterated items.
    fn blake2_256_root(input: Vec<(Vec<u8>, Vec<u8>)>) -> H256 {
        warn!("trie::blake2_256_root() unimplemented");
        H256::default()
    }

    /// A trie root formed from the enumerated items.
    fn blake2_256_ordered_root(input: Vec<Vec<u8>>) -> H256 {
        warn!("trie::blake2_256_ordered_root() unimplemented");
        H256::default()
    }

    fn keccak_256_root(input: Vec<(Vec<u8>, Vec<u8>)>) -> H256 {
        warn!("trie::keccak_256_root() unimplemented");
        H256::default()
	}

	/// A trie root formed from the enumerated items.
	fn keccak_256_ordered_root(input: Vec<Vec<u8>>) -> H256 {
        warn!("trie::keccak_256_ordered_root() unimplemented");
        H256::default()
	}

}

#[runtime_interface]
pub trait Misc {
    /// Print a number.
    fn print_num(val: u64) {
        debug!(target: "runtime", "{}", val);
    }

    /// Print a number.
    fn print_num_version_1(val: u64) {
        debug!(target: "runtime", "{}", val);
    }

    /// Print any valid `utf8` buffer.
    fn print_utf8(utf8: &[u8]) {
        if let Ok(data) = std::str::from_utf8(utf8) {
            debug!(target: "runtime", "{}", data)
        }
    }

    /// Print any `u8` slice as hex.
    fn print_hex(data: &[u8]) {
        debug!(target: "runtime", "{:?}", data);
    }

    fn runtime_version(wasm: &[u8]) -> Option<Vec<u8>> {
        warn!("misc::runtime_version unimplemented!");
        Some([2u8; 32].to_vec())
    }
}

/// Interfaces for working with crypto related types from within the runtime.
#[runtime_interface]
pub trait Crypto {
    fn ed25519_public_keys(id: KeyTypeId) -> Vec<ed25519::Public> {
        warn!("crypto::ed25519_public_keys unimplemented");
        vec![ed25519::Public::default()]
    }

    fn ed25519_generate(id: KeyTypeId, seed: Option<Vec<u8>>) -> ed25519::Public {
        warn!("crypto::ed25519_generate unimplemented");
        ed25519::Public::default()
    }

    fn ed25519_sign(
        id: KeyTypeId,
        pub_key: &ed25519::Public,
        msg: &[u8],
    ) -> Option<ed25519::Signature> {
        warn!("crypto::ed25519_sign unimplemented");
        Some(ed25519::Signature::default())
    }

    fn ed25519_verify(
        sig: &ed25519::Signature,
        msg: &[u8],
        pub_key: &ed25519::Public,
    ) -> bool {
        ed25519::Pair::verify(sig, msg, pub_key)
    }

    fn ed25519_batch_verify(
        sig: &ed25519::Signature,
        msg: &[u8],
        pub_key: &ed25519::Public,
    ) -> bool {
        warn!("crypto::ed25519_batch_verify unimplemented");
        false
    }

	/// Register a `sr25519` signature for batch verification.
	///
	/// Batch verification must be enabled by calling [`start_batch_verify`].
	/// If batch verification is not enabled, the signature will be verified immediatley.
	/// To get the result of the batch verification, [`finish_batch_verify`]
	/// needs to be called.
	///
	/// Returns `true` when the verification is either successful or batched.
	fn sr25519_batch_verify(
		sig: &sr25519::Signature,
		msg: &[u8],
		pub_key: &sr25519::Public,
	) -> bool {
        warn!("crypto::sr25519_batch_verify unimplemented");
        false
	}
            /// Start verification extension.
    fn start_batch_verify() {
        warn!("crypto::start_batch_verify unimplemented");
    }

    fn finish_batch_verify() -> bool {
        warn!("crypto::finish_batch_verify unimplemented");
        true
    }

    fn sr25519_public_keys(id: KeyTypeId) -> Vec<sr25519::Public> {
        warn!("crypto::sr25519_public_key unimplemented");
        vec![sr25519::Public::default()]
    }

    fn sr25519_generate(id: KeyTypeId, seed: Option<Vec<u8>>) -> sr25519::Public {
        warn!("crypto::sr25519_generate unimplemented");
        sr25519::Public::default()
    }

    fn sr25519_sign(
        id: KeyTypeId,
        pubkey: &sr25519::Public,
        msg: &[u8],
    ) -> Option<sr25519::Signature> {
        warn!("crypto::sr25519_sign unimplemented");
        Some(sr25519::Signature::default())
    }

    fn sr25519_verify(sig: &sr25519::Signature, msg: &[u8], pubkey: &sr25519::Public) -> bool {
        sr25519::Pair::verify_deprecated(sig, msg, pubkey)
    }

    /// Verify `sr25519` signature.
	///
	/// Returns `true` when the verification was successful.
	#[version(2)]
	fn sr25519_verify(
		sig: &sr25519::Signature,
		msg: &[u8],
		pub_key: &sr25519::Public,
	) -> bool {
		sr25519::Pair::verify(sig, msg, pub_key)
	}


    /// Returns all `ecdsa` public keys for the given key id from the keystore.
	fn ecdsa_public_keys(id: KeyTypeId) -> Vec<ecdsa::Public> {
        warn!("crypto::ecdsa_public_keys unimplemented");
        Vec::new()
	}

	/// Generate an `ecdsa` key for the given key type using an optional `seed` and
	/// store it in the keystore.
	///
	/// The `seed` needs to be a valid utf8.
	///
	/// Returns the public key.
	fn ecdsa_generate(id: KeyTypeId, seed: Option<Vec<u8>>) -> ecdsa::Public {
        warn!("crypto::ecdsa_generate unimplemented");
        ecdsa::Public::default()
	}

	/// Sign the given `msg` with the `ecdsa` key that corresponds to the given public key and
	/// key type in the keystore.
	///
	/// Returns the signature.
	fn ecdsa_sign(
		id: KeyTypeId,
		pub_key: &ecdsa::Public,
		msg: &[u8],
	) -> Option<ecdsa::Signature> {
        warn!("crypto::ecdsa_sign unimplemented");
        None
	}

	/// Verify `ecdsa` signature.
	///
	/// Returns `true` when the verification was successful.
	fn ecdsa_verify(
		sig: &ecdsa::Signature,
		msg: &[u8],
		pub_key: &ecdsa::Public,
	) -> bool {
		ecdsa::Pair::verify(sig, msg, pub_key)
	}

	/// Register a `ecdsa` signature for batch verification.
	///
	/// Batch verification must be enabled by calling [`start_batch_verify`].
	/// If batch verification is not enabled, the signature will be verified immediatley.
	/// To get the result of the batch verification, [`finish_batch_verify`]
	/// needs to be called.
	///
	/// Returns `true` when the verification is either successful or batched.
	fn ecdsa_batch_verify(
		sig: &ecdsa::Signature,
		msg: &[u8],
		pub_key: &ecdsa::Public,
	) -> bool {
        warn!("crypto::ecdsa_batch_verify unimplemented");
        false
    }

    fn secp256k1_ecdsa_recover(
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<[u8; 64], EcdsaVerifyError> {
        warn!("crypto::secp256k1_ecdsa_recover unimplemented");
        Ok([0; 64])
    }

    fn secp256k1_ecdsa_recover_compressed(
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<[u8; 33], EcdsaVerifyError> {
        warn!("crypto::secp256k1_ecdsa_recover unimplemented");
        Ok([0; 33])
    }
}

 /// Interface that provides functions for hashing with different algorithms.
#[runtime_interface]
pub trait Hashing {
    /// Conduct a 256-bit Keccak hash.
    fn keccak_256(data: &[u8]) -> [u8; 32] {
        sp_core::hashing::keccak_256(data)
    }

    /// Conduct a 512-bit Keccak hash.
	fn keccak_512(data: &[u8]) -> [u8; 64] {
		sp_core::hashing::keccak_512(data)
	}


    /// Conduct a 256-bit Sha2 hash.
    fn sha2_256(data: &[u8]) -> [u8; 32] {
        sp_core::hashing::sha2_256(data)
    }

    /// Conduct a 128-bit Blake2 hash.
    fn blake2_128(data: &[u8]) -> [u8; 16] {
        sp_core::hashing::blake2_128(data)
    }

    /// Conduct a 256-bit Blake2 hash.
    fn blake2_256(data: &[u8]) -> [u8; 32] {
        sp_core::hashing::blake2_256(data)
    }

    /// Conduct four XX hashes to give a 256-bit result.
    fn twox_256(data: &[u8]) -> [u8; 32] {
        sp_core::hashing::twox_256(data)
    }

    /// Conduct two XX hashes to give a 128-bit result.
    fn twox_128(data: &[u8]) -> [u8; 16] {
        sp_core::hashing::twox_128(data)
    }

    /// Conduct two XX hashes to give a 64-bit result.
    fn twox_64(data: &[u8]) -> [u8; 8] {
        sp_core::hashing::twox_64(data)
    }

}

#[runtime_interface]
pub trait OffchainIndex {
    /// Write a key value pair to the Offchain DB database in a buffered fashion.
    fn set(key: &[u8], value: &[u8]) {
        warn!("offchain_index::set unimplemented");
    }

    /// Remove a key and its associated value from the Offchain DB.
    fn clear(key: &[u8]) {
        warn!("offchain_index::clear unimplemented");
    }
}


/// Interface that provides functions to access the offchain functionality.
///
/// These functions are being made available to the runtime and are called by the runtime.
#[runtime_interface]
pub trait Offchain {
    fn is_validator() -> bool {
        warn!("offchain::is_validator unimplemented");
        false
    }

    fn submit_transaction(data: Vec<u8>) -> Result<(), ()> {
        warn!("offchain::submit_transaction unimplemented");
        Err(())
    }

    fn network_state() -> Result<OpaqueNetworkState, ()> {
        warn!("offchain::network_state unimplemented");
        Err(())
    }

    fn timestamp() -> offchain::Timestamp {
        warn!("offchain::timestamp unimplemented");
        offchain::Timestamp::default()
    }

    fn sleep_until(deadline: offchain::Timestamp) {
        warn!("offchain::sleep_until unimplemented");
    }

    fn random_seed() -> [u8; 32] {
        warn!("offchain::random_seed unimplemented");
        [0; 32]
    }

    fn local_storage_set(kind: offchain::StorageKind, key: &[u8], value: &[u8]) {
        warn!("offchain::local_storage_set unimplemented");
    }
    fn local_storage_clear(kind: StorageKind, key: &[u8]) {
        warn!("offchain::local_storage_clear unimplemented");

    }

    fn local_storage_compare_and_set(
        kind: offchain::StorageKind,
        key: &[u8],
        old_value: Option<Vec<u8>>,
        new_value: &[u8],
    ) -> bool {
        warn!("offchain::local_storage_compare_and_set unimplemented");
        false
    }

    fn local_storage_get(kind: offchain::StorageKind, key: &[u8]) -> Option<Vec<u8>> {
        warn!("offchain::local_storage_get unimplemented");
        None
    }

    fn http_request_start(
        method: &str,
        uri: &str,
        meta: &[u8],
    ) -> Result<offchain::HttpRequestId, ()> {
        warn!("offchain::http_request_start unimplemented");
        Err(())
    }

    fn http_request_add_header(
        request_id: offchain::HttpRequestId,
        name: &str,
        value: &str,
    ) -> Result<(), ()> {
        warn!("offchain::http_request_add_header unimplemented");
        Err(())
    }

    fn http_request_write_body(
        request_id: offchain::HttpRequestId,
        chunk: &[u8],
        deadline: Option<offchain::Timestamp>,
    ) -> Result<(), offchain::HttpError> {
        warn!("offchain::http_request_write_body unimplemented");
        Err(offchain::HttpError::IoError)
    }

    fn http_response_wait(
        ids: &[offchain::HttpRequestId],
        deadline: Option<offchain::Timestamp>,
    ) -> Vec<offchain::HttpRequestStatus> {
        warn!("offchain::http_response_wait unimplemented");
        Vec::new()
    }

    fn http_response_headers(request_id: offchain::HttpRequestId) -> Vec<(Vec<u8>, Vec<u8>)> {
        warn!("offchain::http_response_wait unimplemented");
        Vec::new()
    }

    fn http_response_read_body(
        request_id: offchain::HttpRequestId,
        buffer: &mut [u8],
        deadline: Option<offchain::Timestamp>,
    ) -> Result<u32, offchain::HttpError> {
        warn!("offchain::http_response_read_body unimplemented");
        Err(offchain::HttpError::IoError)
    }
}

/// Interface that provides functions for logging from within the runtime.
#[runtime_interface]
pub trait Logging {
    /// Request to print a log message on the host.
    ///
    /// Note that this will be only displayed if the host is enabled to display log messages with
    /// given level and target.
    ///
    /// Instead of using directly, prefer setting up `RuntimeLogger` and using `log` macros.
    fn log(level: LogLevel, target: &str, message: &[u8]) {
        if let Ok(message) = std::str::from_utf8(message) {
            // TODO remove this attention boost
            println!("\x1b[0;36m[{}]\x1b[0m {}", target, message);
            let level = match level {
                LogLevel::Error => sgx_log::Level::Error,
                LogLevel::Warn => sgx_log::Level::Warn,
                LogLevel::Info => sgx_log::Level::Info,
                LogLevel::Debug => sgx_log::Level::Debug,
                LogLevel::Trace => sgx_log::Level::Trace,
            };
            // FIXME: this logs with target sp_io::logging instead of the provided target!
            sgx_log::log!(
                target: target,
                level,
                "{}",
                message,
            );

        }
    }
}


mod tracing_setup {
	/// Initialize tracing of sp_tracing not necessary – noop. To enable build
	/// without std and with the `with-tracing`-feature.
	pub fn init_tracing() { }
}

pub use tracing_setup::init_tracing;

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use sp_core::storage::well_known_keys::CODE;
    use sp_core::{map, H256};

    use super::*;

    #[test]
    fn commit_should_work() {
        let mut ext = SgxExternalities::default();
        ext.set_storage(b"doe".to_vec(), b"reindeer".to_vec());
        ext.set_storage(b"dog".to_vec(), b"puppy".to_vec());
        ext.set_storage(b"dogglesworth".to_vec(), b"cat".to_vec());
        const ROOT: [u8; 32] =
            hex!("39245109cef3758c2eed2ccba8d9b370a917850af3824bc8348d505df2c298fa");

        assert_eq!(ext.storage_root(), H256::from(ROOT));
    }

    #[test]
    fn set_and_retrieve_code() {
        let mut ext = SgxExternalities::default();

        let code = vec![1, 2, 3];
        ext.set_storage(CODE.to_vec(), code.clone());

        assert_eq!(&ext.storage(CODE).unwrap(), &code);
    }

    #[test]
    fn basic_externalities_is_empty() {
        // Make sure no values are set by default in `BasicExternalities`.
        let (storage, child_storage) =
            SgxExternalities::new(Default::default(), Default::default()).into_storages();
        assert!(storage.is_empty());
        assert!(child_storage.is_empty());
    }
}
