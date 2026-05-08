# -----------------------------------------------------------------------------
# Directories
# -----------------------------------------------------------------------------
SOURCE_DIR  := ./source
INCLUDE_DIR := ./include
BUILD_DIR   := ./build
OBJECTS_DIR := $(BUILD_DIR)/objects
DEBUG_DIR   := $(BUILD_DIR)/debug

# -----------------------------------------------------------------------------
# Sources and headers — fully recursive via find
# -----------------------------------------------------------------------------
SOURCES_C := $(shell find $(SOURCE_DIR)  -name "*.c")
HEADERS   := $(shell find $(INCLUDE_DIR) -name "*.h")
OBJECTS   := $(patsubst $(SOURCE_DIR)/%.c, $(OBJECTS_DIR)/%.o, $(SOURCES_C))
DEBUG_OBJ := $(patsubst $(SOURCE_DIR)/%.c, $(DEBUG_DIR)/%.o,   $(SOURCES_C))

# -----------------------------------------------------------------------------
# Toolchain
# -----------------------------------------------------------------------------
CC  := clang
GDB := gdb

# -----------------------------------------------------------------------------
# Flags
# -----------------------------------------------------------------------------
WARNINGS := \
    -Wall -Wextra -Werror -pedantic          \
    -Waddress -Warray-bounds -Wcast-align    \
    -Wconversion -Wfloat-equal -Wformat      \
    -Wimplicit-function-declaration          \
    -Wmissing-prototypes -Wnull-dereference  \
    -Wshadow -Wsign-compare -Wstrict-aliasing\
    -Wuninitialized -Wunused-variable

CFLAGS       := -O0 -I$(INCLUDE_DIR) $(WARNINGS)
DEBUG_FLAGS  := -O0 -g3 -DDEBUG -I$(INCLUDE_DIR) $(WARNINGS)

# -----------------------------------------------------------------------------
# Targets
# -----------------------------------------------------------------------------
.PHONY: all debug clean uncrustify cppcheck

all: $(OBJECTS)

# Release objects — recompile when any header changes
$(OBJECTS_DIR)/%.o: $(SOURCE_DIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Debug objects — same rebuild rule, adds symbols
$(DEBUG_DIR)/%.o: $(SOURCE_DIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(DEBUG_FLAGS) -c $< -o $@

# Build all debug objects then open GDB on each in sequence
debug: $(DEBUG_OBJ)

clean:
	rm -rf $(BUILD_DIR)

# -----------------------------------------------------------------------------
# Uncrustify
# -----------------------------------------------------------------------------
CRUST := $(patsubst $(SOURCE_DIR)/%.c,  $(SOURCE_DIR)/%.uncrustify,  $(SOURCES_C))
CRUST += $(patsubst $(INCLUDE_DIR)/%.h, $(INCLUDE_DIR)/%.uncrustify, $(HEADERS))

uncrustify: $(CRUST)

$(eval $(SOURCE_DIR)/%.uncrustify:  $(SOURCE_DIR)/%.c;  uncrustify -c .uncrustify.cfg -f $$< > $$@)
$(eval $(INCLUDE_DIR)/%.uncrustify: $(INCLUDE_DIR)/%.h; uncrustify -c .uncrustify.cfg -f $$< > $$@)

# -----------------------------------------------------------------------------
# Cppcheck
# -----------------------------------------------------------------------------
cppcheck:
	cppcheck --force -q --check-level=exhaustive --enable=all \
	    $(SOURCES_C) $(HEADERS) -I$(INCLUDE_DIR)              \
	    --checkers-report=cppcheck_report.xml