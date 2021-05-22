#!/bin/bash

# Download the appropriate version of the IPFS cli
IPFS_VERSION="$(go list -f "{{.Version}}" -m github.com/ipfs/go-ipfs)"
go get "github.com/ipfs/go-ipfs/cmd/ipfs@${IPFS_VERSION}"

# Build the IPFS plugin's shared library
mkdir -p build
go build -buildmode=plugin -asmflags=all=-trimpath=\"${GOPATH}\" -gcflags=all=-trimpath=\"${GOPATH}\" -o build/plugin.so ./main/

# Mark the shared library as executable
chmod a+x build/plugin.so

# Install the IPFS plugin in plugins folder
mkdir -p ~/.ipfs/plugins
cp build/plugin.so ~/.ipfs/plugins