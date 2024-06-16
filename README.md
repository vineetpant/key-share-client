# Threshold Encryption Client

This Rust project implements a client to interact with the Threshold Encryption Service. The client can perform encryption and decryption by communicating with the service.

## Features

- **Fetch Public Key**: Retrieve the public key set from the service.
- **Encrypt Message**: Encrypt a plaintext message using the public key set.
- **Decrypt Message**: Decrypt a ciphertext message using decryption shares obtained from the service.

## Prerequisites

- Rust and Cargo installed.
- Dependencies specified in `Cargo.toml`.

## Getting Started

### Configuration

Please make sure the service is running before testing the client and client and service code should be in same folder as client uses service data structs as dependency.

### Install Dependencies

```sh
cargo build
```

### Get Public Key

```sh
cargo run public-key
```

### Encrypt plaintext

```sh
cargo run encrypt --plaintext <plaintext>
```

### Decrypt plaintext

```sh
cargo run decrypt --ciphertext <ciphertext>
```