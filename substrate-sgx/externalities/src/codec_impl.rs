
//! Implement `parity-scale-codec` for the externalities
//!
//! This is little workaround, as `Encode` and `Decode` can't directly be implemented on `HashMap`.

use crate::{SgxExternalitiesType, SgxExternalitiesDiffType};
use std::{vec::Vec};
use sgx_serialize::{SerializeHelper, DeSerializable, DeSerializeHelper};
use codec::{Input, Decode, Encode};

impl Encode for SgxExternalitiesType {
	fn encode(&self) -> Vec<u8> {
		let helper = SerializeHelper::new();
		helper.encode(self).unwrap()
	}
}

impl Decode for SgxExternalitiesType {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		decode_with_deserialize(input)
	}
}

impl Encode for SgxExternalitiesDiffType {
	fn encode(&self) -> Vec<u8> {
		let helper = SerializeHelper::new();
		helper.encode(self.clone()).unwrap()
	}
}

impl Decode for SgxExternalitiesDiffType {
	fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
		decode_with_deserialize(input)
	}
}

fn decode_with_deserialize<I: Input, T: DeSerializable>(input: &mut I) -> Result<T, codec::Error> {
	let mut buff = Vec::with_capacity(input.remaining_len()?
		.ok_or_else(|| codec::Error::from("Could not read length from input data"))?);

	input.read(&mut buff)?;

	DeSerializeHelper::<T>::new(buff).decode().ok_or_else(|| codec::Error::from("Could decode with deserialize"))
}
