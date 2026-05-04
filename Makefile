CC      = gcc
AR      = ar

INC_FLAGS = -I include -I src/core -I src/crypto -I src/sys
CFLAGS    = -std=c11 -Wall -Wextra -Wpedantic -O2 $(INC_FLAGS)
LDFLAGS   = # empty for now

# aes-ni and pclmulqdq intrinsics
AESNI_FLAGS = -maes -mpclmul -msse4.1

SRC_DIR   = src
TEST_DIR  = tests
BUILD_DIR = build
OBJ_DIR   = $(BUILD_DIR)/obj
LIB_DIR   = $(BUILD_DIR)/lib

C_SRCS    = $(shell find $(SRC_DIR) -name '*.c')
C_OBJS    = $(patsubst %.c, $(OBJ_DIR)/%.o, $(notdir $(C_SRCS)))

LIB       = $(LIB_DIR)/libbutane.a

TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_BIN  = $(BUILD_DIR)/test_runner

vpath %.c $(sort $(dir $(C_SRCS)))

.PHONY: all clean test

all: $(LIB)

$(OBJ_DIR) $(LIB_DIR) $(BUILD_DIR):
	mkdir -p $@

# aes256gcm needs hardware intrinsic flags
$(OBJ_DIR)/aes256gcm.o: aes256gcm.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(AESNI_FLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(C_OBJS) | $(LIB_DIR)
	$(AR) rcs $@ $^

$(TEST_BIN): $(TEST_SRCS) $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(TEST_SRCS) -L $(LIB_DIR) -lbutane $(LDFLAGS) -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
