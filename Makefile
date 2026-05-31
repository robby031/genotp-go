.PHONY: all build test fuzz fuzz-clean clean clean-all help

all: build test fuzz

help:
	@echo "Available make targets:"
	@echo "  make build       Build all code"
	@echo "  make test        Run all tests"
	@echo "  make fuzz        Run all fuzzers"
	@echo "  make fuzz-clean  Clean fuzz artifacts"
	@echo "  make clean       Clean build and test artifacts"
	@echo "  make clean-all   Clean everything (including fuzz artifacts)"
	@echo "  make help        Show this help message"

build:
	go build -v ./...

test:
	go test -v ./...

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