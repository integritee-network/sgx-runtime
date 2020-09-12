# SGX-Runtime

Based on [Substrate Node Template](https://github.com/scs/substrate-node-template)

This substrate runtime is instantiated inside a Intel SGX enclave in the [SubstraTEE framework](https://www.substratee.com). Probably all substrate compatible pallets can be integrated and executed confidentially

Until paritytech/substrate#5547 is fixed, we need to patch `sr-io` and `externalities`.
