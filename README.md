# WE32100 COFF Object File Disassembler

This is a disassembler for WE32100 COFF object files (both linked
executables and unlinked objects).

It is a work in progress, and not very good at the moment. However,
it's Good Enough&trade; for some fairly basic usage.

## Usage

```
we32dis [-n <sec>] -h|-i|-s|-d <file>

   -n            Target the named section (e.g. .text, .data)
   -h            Dump file header information
   -i            Dump section information
   -t            Dump symbol table
   -d            Disassemble the named section as WE32100 source
   <file>        The input file
```
## Building

This project is written in Rust (1.31.0 at a minumim). For more
information on Rust, see [The Rust Language Homepage](https://www.rust-lang.org/).
To install Rust, it is very convenient to use [the rustup toolchain installer](https://rustup.rs/),
however, other options are available.

## LICENSE

This project is distributed under the MIT License. See the file
LICENSE.txt for more information.
