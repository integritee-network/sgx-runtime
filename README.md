# SGX-Runtime

Based on [Substrate Node Template](https://github.com/scs/substrate-node-template)

This substrate runtime is instantiated inside a Intel SGX enclave in the [Integritee framework](https://www.substratee.com). Probably all substrate compatible pallets can be integrated and executed confidentially

This repo also hosts our SGX patchese for `sr-io` and `externalities`.

# test build

This crate is meant to be used in SGX environment and may not build on its own.
Therefore, this repo contains a test crate setting up SGX tstd. Build it with:

``` 
cd test_no_std
export SGX_SDK=/opt/intel/sgxsdk
make
```
If it builds without `std` collisions, you're good. Linker errors can be safely ignored.




