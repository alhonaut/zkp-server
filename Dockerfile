FROM rust:1.77

WORKDIR /zkp-server

COPY . .

RUN apt update

RUN apt install -y protobuf-compiler

RUN cargo build --release --bin client