# WebAssembly Build for libsepol

This document describes how to build `libsepol` for WebAssembly using Emscripten.

## Prerequisites

1.  **Emscripten SDK**: Ensure you have Emscripten installed and available in your PATH.
    - Follow the instructions at [emscripten.org](https://emscripten.org/docs/getting_started/downloads.html).
2.  **Build Dependencies**: You need `make`, `flex`, and `bison` installed on your system.
    - On Debian/Ubuntu: `sudo apt-get install make flex bison`

## Compilation Steps

To build `libsepol` for WebAssembly, use the provided `Makefile.wasm`:

```bash
cd libsepol
# Build for Node.js and static library
make -f Makefile.wasm

# Build specifically for the browser example
make -f Makefile.wasm browser
```

### Build Artifacts

- `libsepol/src/libsepol.a`: The static library for linking into other WASM projects.
- `libsepol/src/libsepol_browser.js` / `.wasm`: Unified module for browser use.
- `libsepol/utils/*.js` and `libsepol/utils/*.wasm`: The utility programs as JavaScript/WebAssembly modules (configured for Node.js).

## Usage

### Browser Example

A runnable browser example is provided in `libsepol/wasm_example/`.

1.  Build the browser target: `make -f Makefile.wasm browser`
2.  Serve the root directory with a web server. For example:
    ```bash
    python3 -m http.server 8000
    ```
3.  Navigate to `http://localhost:8000/libsepol/wasm_example/` in your browser.

The example demonstrates how to initialize the library and call `sepol_check_context` using Emscripten's `cwrap`.

### Using Utilities with Node.js

You can run the built utilities using Node.js. Note that due to how WASM files are loaded, you might need to be in the same directory or use a tool that handles the resolution.

```bash
cd libsepol/utils
node chkcon.js
```

### Linking into a WASM Project

To use `libsepol` in your own C/C++ project compiled with Emscripten, include the headers and link against the static library:

```bash
emcc my_app.c -Ipath/to/libsepol/include path/to/libsepol/src/libsepol.a -o my_app.js
```

## Customizing the Build

You can customize the Emscripten flags by editing `libsepol/Makefile.wasm` or by passing them on the command line:

```bash
make -f Makefile.wasm WASM_CFLAGS="-O3" WASM_LDFLAGS="-s EXPORTED_FUNCTIONS=['_sepol_policydb_read']"
```

## Compatibility Notes

- `reallocarray`: Provided via `libsepol/src/wasm_compat.c` to avoid conflicts between Emscripten's `stdlib.h` declaration and the lack of implementation in some environments.
- `SINGLE_FILE=1`: Can be added to `WASM_LDFLAGS` if you wish to embed the WASM binary directly into the JS file.
