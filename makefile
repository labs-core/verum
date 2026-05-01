SOURCE_DIR  := ./source
INCLUDE_DIR := ./include
BUILD_DIR   := ./build
OBJECTS_DIR := $(BUILD_DIR)/objects

SOURCES_C := $(shell find $(SOURCE_DIR) -name "*.c")
HEADERS   := $(wildcard $(INCLUDE_DIR)/*.h) $(wildcard $(INCLUDE_DIR)/*/*.h)
OBJECTS   := $(patsubst $(SOURCE_DIR)/%.c, $(OBJECTS_DIR)/%.o, $(SOURCES_C))

CC     := clang
CFLAGS := -Wall -Wextra -Werror -pedantic -O0 -I$(INCLUDE_DIR) \
          -Waddress -Warray-bounds -Wcast-align -Wconversion \
          -Wfloat-equal -Wformat -Wimplicit-function-declaration \
          -Wmissing-prototypes -Wnull-dereference -Wshadow \
          -Wsign-compare -Wstrict-aliasing -Wuninitialized \
          -Wunused-variable

all: $(OBJECTS)

$(OBJECTS_DIR)/%.o: $(SOURCE_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) compile_commands.json

CRUST  := $(patsubst $(SOURCE_DIR)/%.c, $(SOURCE_DIR)/%.uncrustify, $(SOURCES_C))
CRUST  += $(patsubst $(INCLUDE_DIR)/%.h, $(INCLUDE_DIR)/%.uncrustify, $(HEADERS))

uncrustify: $(CRUST)
$(eval $(SOURCE_DIR)/%.uncrustify: $(SOURCE_DIR)/%.c; uncrustify -c .uncrustify.cfg -f $$< > $$@)
$(eval $(INCLUDE_DIR)/%.uncrustify: $(INCLUDE_DIR)/%.h; uncrustify -c .uncrustify.cfg -f $$< > $$@)

cppcheck:
	cppcheck --force -q --check-level=exhaustive --enable=all \
		$(SOURCES_C) $(HEADERS) -I$(INCLUDE_DIR) \
		--checkers-report=cppcheck_report.xml

.PHONY: all clean uncrustify cppcheck 