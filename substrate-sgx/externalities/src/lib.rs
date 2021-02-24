#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate sgx_tstd as std;

use std::{collections::HashMap, vec::Vec};

#[cfg(not(feature = "std"))]
use sgx_serialize::{DeSerializeHelper, SerializeHelper};
use sgx_serialize_derive::{Serializable, DeSerializable};

use environmental::environmental;

pub type SgxExternalitiesType = HashMap<Vec<u8>, Vec<u8>>;

#[cfg(not(feature = "std"))]
#[derive(Serializable, DeSerializable)]
pub struct SgxExternalities {
    pub state: SgxExternalitiesType,
    pub state_diff: SgxExternalitiesType,
}

environmental!(ext: SgxExternalities);

pub trait SgxExternalitiesTrait {
    fn new() -> Self;
    fn decode(state: Vec<u8>) -> Self;
    fn encode(self) -> Vec<u8>;
    fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) -> Option<Vec<u8>>;
    fn remove(&mut self, k: &[u8]) -> Option<Vec<u8>>;
    fn get(&mut self, k: &[u8]) -> Option<&Vec<u8>>;
    fn contains_key(&mut self, k: &[u8]) -> bool;
    fn execute_with<R>(&mut self, f: impl FnOnce() -> R) -> R;
}

#[cfg(not(feature = "std"))]
impl SgxExternalitiesTrait for SgxExternalities {
    /// Create a new instance of `BasicExternalities`
    fn new() -> Self {
        SgxExternalities{
            state: Default::default(),
            state_diff: Default::default(),
        }
    }
 
    fn decode(state: Vec<u8>) -> Self {
        let helper = DeSerializeHelper::<SgxExternalities>::new(state);
        helper.decode().unwrap()
    }

    fn encode(self) -> Vec<u8> {
        let helper = SerializeHelper::new();
        helper.encode(self).unwrap()
    }

    /// Insert key/value
    fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) -> Option<Vec<u8>> {
        self.state_diff.insert(k.clone(), v.clone());
        self.state.insert(k, v)
    }

    /// remove key
    fn remove(&mut self, k: &[u8]) -> Option<Vec<u8>> {
        self.state_diff.remove(k.clone());
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
