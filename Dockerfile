FROM rust
COPY ./target/release/druntime-rs /usr/local/bin/druntime-rs
ENV CFG_PATH=/etc/druntime/prod.ini
CMD druntime-rs --cfg ${CFG_PATH}