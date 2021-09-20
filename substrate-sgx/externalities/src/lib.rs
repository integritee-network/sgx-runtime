/*
    Copyright 2021 Integritee AG and Supercomputing Systems AG

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate sgx_tstd as std;

use std::{collections::HashMap, vec::Vec};
use codec::{Encode, Decode};
use derive_more::{From, Deref, DerefMut};
use environmental::environmental;

#[cfg(not(feature = "std"))]
use sgx_serialize_derive::{DeSerializable, Serializable};

#[cfg(not(feature = "std"))]
mod codec_impl;

// new-type pattern to implement `Encode` `Decode` for Hashmap.
#[cfg_attr(not(feature = "std"), derive(Serializable, DeSerializable))]
#[derive(From, Deref, DerefMut, Debug, Default, PartialEq, Eq, Clone)]
pub struct SgxExternalitiesType(HashMap<Vec<u8>, Vec<u8>>);
#[cfg_attr(not(feature = "std"), derive(Serializable, DeSerializable))]
#[derive(From, Deref, DerefMut, Debug, Default, PartialEq, Eq, Clone)]
pub struct SgxExternalitiesDiffType(HashMap<Vec<u8>, Option<Vec<u8>>>);

#[cfg_attr(not(feature = "std"), derive(Serializable, DeSerializable, Encode, Decode))]
#[derive(Debug, Clone)]
pub struct SgxExternalities {
	pub state: SgxExternalitiesType,
	pub state_diff: SgxExternalitiesDiffType,
}

environmental!(ext: SgxExternalities);

pub trait SgxExternalitiesTrait: {
	fn new() -> Self;
	fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) -> Option<Vec<u8>>;
	fn remove(&mut self, k: &[u8]) -> Option<Vec<u8>>;
	fn get(&mut self, k: &[u8]) -> Option<&Vec<u8>>;
	fn contains_key(&mut self, k: &[u8]) -> bool;
	fn prune_state_diff(&mut self);
	fn execute_with<R>(&mut self, f: impl FnOnce() -> R) -> R;
}

impl SgxExternalitiesType {
	fn new() -> Self {
		Default::default()
	}
}

impl SgxExternalitiesDiffType {
	fn new() -> Self {
		Default::default()
	}
}

impl SgxExternalitiesTrait for SgxExternalities {
	/// Create a new instance of `BasicExternalities`
	fn new() -> Self {
		SgxExternalities {
			state: SgxExternalitiesType::new(),
			state_diff: SgxExternalitiesDiffType::new(),
		}
	}

	/// Insert key/value
	fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) -> Option<Vec<u8>> {
		self.state_diff.insert(k.clone(), Some(v.clone()));
		self.state.insert(k, v)
	}

	/// remove key
	fn remove(&mut self, k: &[u8]) -> Option<Vec<u8>> {
		self.state_diff.insert(k.to_vec(), None);
		self.state.remove(k)
	}

	/// get value from state of key
	fn get(&mut self, k: &[u8]) -> Option<&Vec<u8>> {
		self.state.get(k)
	}

	/// check if state contains key
	fn contains_key(&mut self, k: &[u8]) -> bool {
		self.state.contains_key(k)
	}

	/// prunes the state diff
	fn prune_state_diff(&mut self) {
		self.state_diff.clear();
	}

	/// Execute the given closure while `self` is set as externalities.
	///
	/// Returns the result of the given closure.
	fn execute_with<R>(&mut self, f: impl FnOnce() -> R) -> R {
		set_and_run_with_externalities(self, f)
	}
}

/// Set the given externalities while executing the given closure. To get access to the externalities
/// while executing the given closure [`with_externalities`] grants access to them. The externalities
/// are only set for the same thread this function was called from.
pub fn set_and_run_with_externalities<F: FnOnce() -> R, R>(ext: &mut SgxExternalities, f: F) -> R {
	ext::using(ext, f)
}

/// Execute the given closure with the currently set externalities.
///
/// Returns `None` if no externalities are set or `Some(_)` with the result of the closure.
pub fn with_externalities<F: FnOnce(&mut SgxExternalities) -> R, R>(f: F) -> Option<R> {
	ext::with(f)
}
