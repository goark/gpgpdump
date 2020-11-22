#!/bin/bash
go mod verify || exit 1
go mod tidy -v || exit 1
depm list --json | nancy sleuth -n || exit 1
golangci-lint run ./... || exit 1
go test ./... || exit 1
depm m --dot --dot-config dot-config.toml | dot -Tpng -o dependency.png
