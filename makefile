build: 
	cargo build --release
dev:
	cargo run -- --cfg /Users/xiongyi/Desktop/saas3/druntime-rs/dev.ini
release-run:
	./target/release/druntime-rs --cfg /Users/xiongyi/Desktop/saas3/druntime-rs/dev.ini