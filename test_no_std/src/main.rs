#![feature(start, libc, lang_items)]
#![feature(alloc_error_handler)]
#![no_std]
#![no_main]


extern crate sgx_tstd as std;
// extern crate rstd;
// DUT

// The libc crate allows importing functions from C.
extern crate libc;

// A list of C functions that are being imported
extern {
    pub fn printf(format: *const u8, ...) -> i32;
}

#[no_mangle]
// The main function, with its input arguments ignored, and an exit status is returned
pub extern fn main(_nargs: i32, _args: *const *const u8) -> i32 {
    // Print "Hello, World" to stdout using printf
    unsafe { 
        printf(b"Hello, World!\n" as *const u8);
    }

    // Exit with a return status of 0.
    0
}