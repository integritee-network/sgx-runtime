//! Implement `parity-scale-codec` for the externalities.
//!
//! This is little workaround, as `Encode` and `Decode` can't directly be implemented on `HashMap`.

use crate::{SgxExternalitiesDiffType, SgxExternalitiesType};
use codec::{Decode, Encode, Input};
use sgx_serialize::{DeSerializable, DeSerializeHelper, Serializable, SerializeHelper};
use std::vec::Vec;

impl Encode for SgxExternalitiesType {
	fn encode(&self) -> Vec<u8> {
		encode_with_serialize(self)
	}
}

impl Decode for SgxExternalitiesType {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		decode_with_deserialize(input)
	}
}

impl Encode for SgxExternalitiesDiffType {
	fn encode(&self) -> Vec<u8> {
		encode_with_serialize(self)
	}
}

impl Decode for SgxExternalitiesDiffType {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		decode_with_deserialize(input)
	}
}

fn encode_with_serialize<T: Serializable>(source: &T) -> Vec<u8> {
	match SerializeHelper::new().encode(source) {
		Some(t) => t,
		None => {
			sgx_log::warn!("`encode_with_serialize` returned None");
			Default::default()
		},
	}
}

fn decode_with_deserialize<I: Input, T: DeSerializable>(input: &mut I) -> Result<T, codec::Error> {
	let mut buff = Vec::with_capacity(
		input
			.remaining_len()?
			.ok_or_else(|| codec::Error::from("Could not read length from input data"))?,
	);

	input.read(&mut buff)?;

	DeSerializeHelper::<T>::new(buff)
		.decode()
		.ok_or_else(|| codec::Error::from("Could not decode with deserialize"))
}
