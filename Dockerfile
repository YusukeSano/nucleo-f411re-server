FROM rust:latest
RUN rustup target add thumbv7em-none-eabihf
WORKDIR /usr/src/app
