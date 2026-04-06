# Game of Life WASM build
EMCC = emcc
CFLAGS = -O2 -Wall -Wextra
SOURCES = hashtable.c gol.c
OUTPUT_DIR = ../app/static/wasm
OUTPUT = $(OUTPUT_DIR)/gol.js

EXPORTED_FUNCTIONS = '["_gol_init","_gol_step","_gol_get_cells","_gol_cell_count","_gol_reset","_gol_spawn","_gol_set_bounds","_malloc","_free"]'
EXPORTED_RUNTIME = '["ccall","cwrap","HEAP32","wasmMemory"]'

.PHONY: all clean dirs

all: dirs $(OUTPUT)

dirs:
	@mkdir -p $(OUTPUT_DIR)

$(OUTPUT): $(SOURCES) gol.h
	$(EMCC) $(SOURCES) $(CFLAGS) \
		-s WASM=1 \
		-s EXPORTED_FUNCTIONS=$(EXPORTED_FUNCTIONS) \
		-s EXPORTED_RUNTIME_METHODS=$(EXPORTED_RUNTIME) \
		-s ALLOW_MEMORY_GROWTH=1 \
		-s INITIAL_MEMORY=1048576 \
		-s MODULARIZE=1 \
		-s EXPORT_NAME='GOLModule' \
		-I. \
		-o $(OUTPUT)

clean:
	rm -f $(OUTPUT_DIR)/gol.js $(OUTPUT_DIR)/gol.wasm

# Native build for local testing (no WASM)
native: $(SOURCES) gol.h
	gcc $(SOURCES) -O2 -Wall -Wextra -std=c2x -I. -lm -o gol_test
