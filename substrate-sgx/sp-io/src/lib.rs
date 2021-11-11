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

//#![warn(missing_docs)]

// Added by Integritee. Prevents warnings during compilation with sgx features at all those
// unimplemented method stubs.
#![allow(unused_variables)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(lang_items))]
#![cfg_attr(not(feature = "std"), feature(alloc_error_handler))]
#![cfg_attr(not(feature = "std"), feature(core_intrinsics))]
#![cfg_attr(
	feature = "std",
	doc = "Substrate runtime standard library as compiled when linked with Rust's standard library."
)]
#![cfg_attr(
	not(feature = "std"),
	doc = "Substrate's runtime standard library as compiled without Rust's standard library."
)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

// Starting from here, the content of the lib.rs file has been moved to without_sgx.rs.

#[cfg(all(not(feature = "sgx"), feature = "std"))]
include!("../without_sgx.rs");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
include!("../with_sgx.rs");
