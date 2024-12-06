# Chaum Pederson Zero Knowledge Proof in Rust

This repository contains an implementation of the **Chaum-Pederson Zero Knowledge Proof (ZKP)** protocol in **Rust**, which is used for verifying authentication without revealing the underlying secret. The project includes:

- A **gRPC server** (`server.rs`) for handling user registration, proof creation, and verification.
- A **Rust library** (`lib.rs`) that implements the core zero-knowledge proof functionality.
- A **client** (`client.rs`) to send requests to the server.
- **Docker** setup to containerize the project for easy deployment and execution in any environment.

## Project Structure

- **`server.rs`**: The gRPC server implementation. It handles:
  - User registration (`register`)
  - Creation of authentication challenges (`create_authentication_challenge`)
  - Verification of authentication proofs (`verify_authentication`)

- **`lib.rs`**: The library for the zero-knowledge proof algorithm implementation, which includes:
  - Calculation of values (`y1`, `y2`, `r1`, `r2`, `s`)
  - Verification of the proof (`verify`)

- **`client.rs`**: The client code to interact with the gRPC server and request user registration, challenge creation, and proof verification.

- **`zkp_auth.proto`**: Protocol Buffers file that defines the gRPC service and message types used for communication between the client and server.

## Features

- **Zero Knowledge Proof**: Implements Chaum-Pederson ZKP for authentication without revealing the secret.
- **gRPC Server**: Provides an API for user registration, challenge creation, and proof verification.
- **Dockerized**: The entire project can be run within a Docker container for easy setup and deployment.
- **Multi-Environment Compatibility**: With Docker, you can run the project on any system without worrying about dependencies or configurations.

## Prerequisites

- **Rust**: Version 1.60 or higher.
- **Docker**: To run the project in containers.
- **Protobuf Compiler (protoc)**: For generating Rust code from `.proto` files (used by gRPC).
  
### Optional

- **Postman/Insomnia**: To test the gRPC server via HTTP/REST endpoints.

## Setting Up the Project

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/chaum-pederson-zkp.git
    cd chaum-pederson-zkp
    ```

2. Install dependencies:
    - Make sure you have **Rust** and **Cargo** installed. If not, follow the installation guide at [https://www.rust-lang.org/learn/get-started](https://www.rust-lang.org/learn/get-started).
    - Install **Protobuf Compiler** if you don't have it. On macOS, you can install it via `brew`:
      ```bash
      brew install protobuf
      ```

3. Generate Rust files from the `.proto` file:
    ```bash
    protoc --rust_out=src --tonic_out=src zkp_auth.proto
    ```

## Running the Project with Docker

1. **Build the Docker image**:
    - Make sure you are in the project directory, then run:
    ```bash
    docker build -t zkp-server .
    ```

2. **Run the Docker container**:
    - Start the gRPC server in a Docker container with the following command:
    ```bash
    docker run -p 50051:50051 zkp-server
    ```

    This will expose the gRPC server on port `50051`.

3. **Run the client**:
    - You can either run the client code from `client.rs` or interact with the gRPC server using a tool like Postman or Insomnia. Ensure the client connects to `127.0.0.1:50051` to send requests to the server.

## Dockerfile

Here’s the `Dockerfile` used to containerize the project:

```dockerfile
FROM rust:1.60

# Install protobuf compiler
RUN apt-get update && apt-get install -y protobuf-compiler

# Create app directory
WORKDIR /app

# Copy the source code
COPY . .

# Install dependencies
RUN cargo build --release

# Expose the server port
EXPOSE 50051

# Run the server
CMD ["cargo", "run", "--release", "--bin", "server"]
