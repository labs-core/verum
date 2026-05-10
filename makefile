# =============================================================================
# Directories
# =============================================================================
SOURCE_DIR   := ./source
INCLUDE_DIR  := ./include
BUILD_DIR    := ./build
OBJECTS_DIR  := $(BUILD_DIR)/objects
TEST_DIR     := ./test
TEST_OBJ_DIR := $(BUILD_DIR)/test
UNITY_DIR    := $(TEST_DIR)/unity

# =============================================================================
# Sources, headers, and object derivation
# =============================================================================
SOURCES_C := $(shell find $(SOURCE_DIR) -name "*.c")
HEADERS   := $(shell find $(INCLUDE_DIR) -name "*.h")

# Production objects → build/objects/<mirror of source/>
OBJECTS   := $(patsubst $(SOURCE_DIR)/%.c, $(OBJECTS_DIR)/%.o, $(SOURCES_C))

# Test objects (all .c under test/, including unity) → build/test/<mirror of test/>
TEST_SRCS_C := $(shell find $(TEST_DIR) -name "*.c")
TEST_OBJ    := $(patsubst $(TEST_DIR)/%.c, $(TEST_OBJ_DIR)/%.o, $(TEST_SRCS_C))

TEST_BIN    := $(BUILD_DIR)/test_runner

# =============================================================================
# Toolchain
# =============================================================================
CC  := clang
GDB := gdb

# =============================================================================
# Flags
# =============================================================================
WARNINGS := \
    -Wall -Wextra -Werror -pedantic              \
    -Waddress -Warray-bounds -Wcast-align        \
    -Wcast-qual -Wbad-function-cast              \
    -Wconversion -Wdouble-promotion              \
    -Wformat=2                                   \
    -Wimplicit-function-declaration              \
    -Wimplicit-fallthrough                       \
    -Wmissing-declarations                       \
    -Wmissing-prototypes                         \
    -Wmissing-variable-declarations              \
    -Wnull-dereference                           \
    -Wpointer-arith                              \
    -Wreserved-identifier                        \
    -Wshadow -Wsign-compare -Wstrict-aliasing    \
    -Wstrict-overflow=2 -Wstrict-prototypes      \
    -Wswitch-default -Wswitch-enum               \
    -Wundef -Wuninitialized                      \
    -Wunused-macros -Wunused-variable            \
    -Wvla -g3

# Release flags (default)
CFLAGS := -O0 -I$(INCLUDE_DIR) $(WARNINGS)

# Debug: same object dir, only flags change — invoke with: make DEBUG=1
# Note: run 'make clean' first when switching modes to avoid stale objects
ifdef DEBUG
CFLAGS := -O0 -g3 -DDEBUG \
           -fsanitize=address,undefined \
           -I$(INCLUDE_DIR) $(WARNINGS)
endif

# Test flags extend whatever CFLAGS is (release or debug)
TEST_FLAGS := $(CFLAGS) -I$(UNITY_DIR)

# =============================================================================
# Phony targets
# =============================================================================
.PHONY: all debug test test-clean clean uncrustify cppcheck

# =============================================================================
# all — production objects into build/objects/
# =============================================================================
all: $(OBJECTS)

$(OBJECTS_DIR)/%.o: $(SOURCE_DIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# =============================================================================
# debug — rebuild production objects with debug flags
#         run 'make clean' first when switching from release to avoid stale objects
# =============================================================================
debug:
	$(MAKE) DEBUG=1 all

# =============================================================================
# test — test objects mirror test/ into build/test/
#        links against production objects already in build/objects/
# =============================================================================
$(TEST_OBJ_DIR)/%.o: $(TEST_DIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(TEST_FLAGS) -c $< -o $@

$(TEST_BIN): $(OBJECTS) $(TEST_OBJ)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $^ -o $@

test: $(OBJECTS) $(TEST_BIN)
	@echo "━━━ Running unit tests ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@./$(TEST_BIN); EXIT=$$?;                                    \
	 echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; \
	 exit $$EXIT

test-clean:
	$(RM) -r $(TEST_OBJ_DIR) $(TEST_BIN)

# =============================================================================
# clean
# =============================================================================
clean:
	rm -rf $(BUILD_DIR)

# =============================================================================
# Uncrustify
# =============================================================================
.PHONY: uncrustify

uncrustify:
	uncrustify -c .uncrustify.cfg --replace --no-backup $(SOURCES_C) $(HEADERS)

# =============================================================================
# Cppcheck
# =============================================================================
cppcheck:
	cppcheck --force -q --check-level=exhaustive --enable=all \
	    $(SOURCES_C) $(HEADERS) -I$(INCLUDE_DIR)              \
	    --checkers-report=cppcheck_report.xml