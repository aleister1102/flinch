# Makefile for httpfuzz project

BINARY_FUZZY=fuzzy
BINARY_SURVEY=survey
BINARY_FEATURES=features
BINARY_FILTER=filterResponses

BIN_DIR=bin
INSTALL_PATH=$(HOME)/.local/bin
CURRENT_TAG := $(shell git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)

.PHONY: build clean test install uninstall release

build:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY_FUZZY) cmd/fuzzy/main.go
	go build -o $(BIN_DIR)/$(BINARY_SURVEY) cmd/survey/main.go
	go build -o $(BIN_DIR)/$(BINARY_FEATURES) cmd/features/main.go
	go build -o $(BIN_DIR)/$(BINARY_FILTER) cmd/filterResponses/main.go

test:
	go test ./...

install: build
	mkdir -p $(INSTALL_PATH)
	cp $(BIN_DIR)/$(BINARY_FUZZY) $(INSTALL_PATH)/$(BINARY_FUZZY)
	cp $(BIN_DIR)/$(BINARY_SURVEY) $(INSTALL_PATH)/$(BINARY_SURVEY)
	cp $(BIN_DIR)/$(BINARY_FEATURES) $(INSTALL_PATH)/$(BINARY_FEATURES)
	cp $(BIN_DIR)/$(BINARY_FILTER) $(INSTALL_PATH)/$(BINARY_FILTER)
	chmod +x $(INSTALL_PATH)/$(BINARY_FUZZY)
	chmod +x $(INSTALL_PATH)/$(BINARY_SURVEY)
	chmod +x $(INSTALL_PATH)/$(BINARY_FEATURES)
	chmod +x $(INSTALL_PATH)/$(BINARY_FILTER)

uninstall:
	rm $(INSTALL_PATH)/$(BINARY_FUZZY)
	rm $(INSTALL_PATH)/$(BINARY_SURVEY)
	rm $(INSTALL_PATH)/$(BINARY_FEATURES)
	rm $(INSTALL_PATH)/$(BINARY_FILTER)

clean:
	rm -rf $(BIN_DIR)

release:
	@if [ -z "$(VERSION)" ]; then echo "VERSION is not set"; exit 1; fi
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION)
