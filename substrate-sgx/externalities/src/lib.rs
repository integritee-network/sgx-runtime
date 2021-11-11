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

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use codec::{Decode, Encode};
use derive_more::{Deref, DerefMut, From};
use environmental::environmental;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::{collections::BTreeMap, vec::Vec};

mod codec_impl;

// new-type pattern to implement `Encode` `Decode` for Hashmap.
#[serde_as]
#[derive(From, Deref, DerefMut, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SgxExternalitiesType(#[serde_as(as = "Vec<(_, _)>")] BTreeMap<Vec<u8>, Vec<u8>>);

#[serde_as]
#[derive(From, Deref, DerefMut, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SgxExternalitiesDiffType(
	#[serde_as(as = "Vec<(_, _)>")] BTreeMap<Vec<u8>, Option<Vec<u8>>>,
);

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct SgxExternalities {
	pub state: SgxExternalitiesType,
	pub state_diff: SgxExternalitiesDiffType,
}

environmental!(ext: SgxExternalities);

pub trait SgxExternalitiesTrait {
	fn new() -> Self;
	fn state(&self) -> &SgxExternalitiesType;
	fn state_diff(&self) -> &SgxExternalitiesDiffType;
	fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) -> Option<Vec<u8>>;
	fn remove(&mut self, k: &[u8]) -> Option<Vec<u8>>;
	fn get(&self, k: &[u8]) -> Option<&Vec<u8>>;
	fn contains_key(&self, k: &[u8]) -> bool;
	fn prune_state_diff(&mut self);
	fn execute_with<R>(&mut self, f: impl FnOnce() -> R) -> R;
}

impl SgxExternalitiesTrait for SgxExternalities {
	/// Create a new instance of `BasicExternalities`
	fn new() -> Self {
		Default::default()
	}

	fn state(&self) -> &SgxExternalitiesType {
		&self.state
	}

	fn state_diff(&self) -> &SgxExternalitiesDiffType {
		&self.state_diff
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
	fn get(&self, k: &[u8]) -> Option<&Vec<u8>> {
		self.state.get(k)
	}

	/// check if state contains key
	fn contains_key(&self, k: &[u8]) -> bool {
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
