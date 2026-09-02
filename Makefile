APP := gpg-wrapper

.PHONY: build run install clean

build:
	cargo build --release

run:
	cargo run --release

install: build
	install -Dm755 target/release/$(APP) $(DESTDIR)/usr/local/bin/$(APP)
	install -Dm644 $(APP).desktop $(DESTDIR)/usr/share/applications/$(APP).desktop

clean:
	cargo clean
