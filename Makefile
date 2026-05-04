CC      = gcc
AR      = ar

CFLAGS    = -std=c11 -Wall -Wextra -Wpedantic -O2 -I include -I src
LDFLAGS   = # empty for now

# aes-ni and pclmulqdq intrinsics
AESNI_FLAGS = -maes -mpclmul -msse4.1

SRC_DIR   = src
TEST_DIR  = tests
BUILD_DIR = build
OBJ_DIR   = $(BUILD_DIR)/obj
LIB_DIR   = $(BUILD_DIR)/lib

C_SRCS    = $(wildcard $(SRC_DIR)/*.c)
C_OBJS    = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(C_SRCS))
LIB       = $(LIB_DIR)/libbutane.a

TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_BIN  = $(BUILD_DIR)/test_runner

.PHONY: all clean test

all: $(LIB)

$(OBJ_DIR) $(LIB_DIR) $(BUILD_DIR):
	mkdir -p $@

# aes256gcm needs hardware intrinsic flags
$(OBJ_DIR)/aes256gcm.o: $(SRC_DIR)/aes256gcm.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(AESNI_FLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(C_OBJS) | $(LIB_DIR)
	$(AR) rcs $@ $^

$(TEST_BIN): $(TEST_SRCS) $(LIB) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(TEST_SRCS) -L $(LIB_DIR) -lbutane $(LDFLAGS) -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
