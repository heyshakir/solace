# Usage: 
#   make build-all   (Builds for both Windows and Linux)
#   make clean       (Removes the bin folder)

APP_NAME = solace
BUILD_DIR = bin

.PHONY: all clean build-windows build-linux build-all

all: build-all

build-windows:
	@echo "Building for Windows..."
	@GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME).exe ./cmd/toolkit/main.go
	@echo "✔ Windows build complete: $(BUILD_DIR)/$(APP_NAME).exe"

build-linux:
	@echo "Building for Linux..."
	@GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME)-linux ./cmd/toolkit/main.go
	@echo "✔ Linux build complete: $(BUILD_DIR)/$(APP_NAME)-linux"

build-all: build-windows build-linux

clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)