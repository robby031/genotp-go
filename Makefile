.PHONY: all build test bench bench-short fuzz fuzz-clean clean clean-all build-wasm help

WASM_OUT ?= ../../js/genotp-serverless/wasm/genotp.wasm

all: build test fuzz

build-wasm:
	cd wasm && GOOS=wasip1 GOARCH=wasm go build -ldflags="-s -w" -o $(WASM_OUT) .
	@echo "WASM built -> $(WASM_OUT) ($$(du -sh $(WASM_OUT) | cut -f1))"

help:
	@echo "Available make targets:"
	@echo "  make build       Build all code"
	@echo "  make build-wasm  Compile WASM module -> $(WASM_OUT)"
	@echo "  make test        Run all tests"
	@echo "  make bench       Run all benchmarks with -benchmem"
	@echo "  make bench-short Run benchmarks with short -benchtime (smoke)"
	@echo "  make fuzz        Run all fuzzers"
	@echo "  make fuzz-clean  Clean fuzz artifacts"
	@echo "  make clean       Clean build and test artifacts"
	@echo "  make clean-all   Clean everything (including fuzz artifacts)"
	@echo "  make help        Show this help message"

build:
	go build -v ./...

test:
	go test -v ./...

bench:
	go test ./tests -run=^$$ -bench=. -benchmem

bench-short:
	go test ./tests -run=^$$ -bench=. -benchmem -benchtime=200ms

fuzz:
	@for f in $$(grep -h -o 'func \(Fuzz[^( ]*\)' fuzz/*_fuzz_test.go | sed 's/func //' | sort | uniq); do \
		echo "Running go test -fuzz=$$f -run=^$$ -v"; \
		go test ./fuzz -run=^$$ -fuzz=$$f -fuzztime=10s -v; \
	done

fuzz-clean:
	rm -rf fuzz/testdata
	@echo "Fuzz artifacts cleaned."

clean:
	rm -f *.out *.exe *.test
	go clean -cache -testcache -modcache
	@echo "Build and test artifacts cleaned."

clean-all: 
	$(MAKE) clean fuzz-clean
	rm -f genotp-go
	@echo "All artifacts cleaned."