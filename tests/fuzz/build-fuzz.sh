#!/usr/bin/env bash

# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: Apache-2.0
set -eu
cd "$(dirname "$0")/../.."

command -v clang >/dev/null || { echo "clang required for the fuzzer" >&2; exit 1; }
mkdir -p build-fuzz/corpus build-fuzz/corpus-images

# Seed the decoder corpus with a valid OSON magic so the fuzzer reaches the tree walk.
printf '\xff\x4a\x5a\x00\x00\x00\x00\x00' > build-fuzz/corpus/oson_magic
# Seed the image corpus with a small object-image-shaped buffer.
printf '\x84\x01\x10\x00\x00' > build-fuzz/corpus-images/seed

FUZZ_FLAGS="-g -O1 -fsanitize=fuzzer,address,undefined -D_GNU_SOURCE \
  -Iinclude -Isrc/tns -Isrc/common"

# --- fuzz_decoders: pure decoder sources only -------------------------------
clang $FUZZ_FLAGS \
  tests/fuzz/fuzz_decoders.c \
  src/tns/oson.c src/tns/json.c src/tns/types.c src/tns/marshal.c \
  src/tns/reader.c src/tns/writer.c src/common/*.c \
  -o build-fuzz/fuzz_decoders
echo "built build-fuzz/fuzz_decoders"

# --- fuzz_images: whole TNS core, image decoders exposed via -DSEER_FUZZ -----
clang $FUZZ_FLAGS -DSEER_FUZZ \
  tests/fuzz/fuzz_images.c \
  src/tns/*.c src/common/*.c \
  -lssl -lcrypto -lpthread \
  -o build-fuzz/fuzz_images
echo "built build-fuzz/fuzz_images"
