```sh
INF  [==========] Running all tests.
INF  [ RUN      ] CborWriterTest.Int1ByteEncoding
INF  Int1ByteEncoding:
INF   0x00
INF   0x17
INF   0x20
INF   0x37
INF  [       OK ] CborWriterTest.Int1ByteEncoding
INF  [ RUN      ] CborWriterTest.Int2Bytes
INF  Int2Bytes:
INF   0x18
INF   0x18
INF   0x18
INF   0xff
INF   0x38
INF   0x18
INF   0x38
INF   0xff
INF  [       OK ] CborWriterTest.Int2Bytes
INF  [ RUN      ] CborWriterTest.Int3Bytes
INF  Int3Bytes:
INF   0x19
INF   0x01
INF   0x00
INF   0x19
INF   0xff
INF   0xff
INF   0x39
INF   0x01
INF   0x00
INF   0x39
INF   0xff
INF   0xff
INF  [       OK ] CborWriterTest.Int3Bytes
INF  [ RUN      ] CborWriterTest.Int5Bytes
INF  Int5Bytes:
INF   0x1a
INF   0x00
INF   0x01
INF   0x00
INF   0x00
INF   0x1a
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0x3a
INF   0x00
INF   0x01
INF   0x00
INF   0x00
INF   0x3a
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF  [       OK ] CborWriterTest.Int5Bytes
INF  [ RUN      ] CborWriterTest.Int9Bytes
INF  Int9Bytes:
INF   0x1b
INF   0x00
INF   0x00
INF   0x00
INF   0x01
INF   0x00
INF   0x00
INF   0x00
INF   0x00
INF   0x1b
INF   0x7f
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0x3b
INF   0x00
INF   0x00
INF   0x00
INF   0x01
INF   0x00
INF   0x00
INF   0x00
INF   0x00
INF   0x3b
INF   0x7f
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF  [       OK ] CborWriterTest.Int9Bytes
INF  [ RUN      ] CborWriterTest.Uint9Bytes
INF  Uint9Bytes:
INF   0x1b
INF   0x00
INF   0x00
INF   0x00
INF   0x01
INF   0x00
INF   0x00
INF   0x00
INF   0x00
INF   0x1b
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF   0xff
INF  [       OK ] CborWriterTest.Uint9Bytes
INF  [ RUN      ] CborWriterTest.IntByteOrder
INF  IntByteOrder:
INF   0x19
INF   0x12
INF   0x34
INF   0x1a
INF   0x12
INF   0x34
INF   0x56
INF   0x78
INF   0x1b
INF   0x12
INF   0x34
INF   0x56
INF   0x78
INF   0x9a
INF   0xbc
INF   0xde
INF   0xf0
INF  [       OK ] CborWriterTest.IntByteOrder
INF  [ RUN      ] CborWriterTest.BstrEncoding
INF  BstrEncoding:
INF   0x45
INF   0x68
INF   0x65
INF   0x6c
INF   0x6c
INF   0x6f
INF  [       OK ] CborWriterTest.BstrEncoding
INF  [ RUN      ] CborWriterTest.BstrAllocEncoding
INF  BstrAllocEncoding:
INF   0x45
INF   0x61
INF   0x6c
INF   0x6c
INF   0x6f
INF   0x63
INF  [       OK ] CborWriterTest.BstrAllocEncoding
INF  [ RUN      ] CborWriterTest.TstrEncoding
INF  TstrEncoding:
INF   0x65
INF   0x77
INF   0x6f
INF   0x72
INF   0x6c
INF   0x64
INF  [       OK ] CborWriterTest.TstrEncoding
INF  [ RUN      ] CborWriterTest.TstrAllocEncoding
INF  TstrAllocEncoding:
INF   0x65
INF   0x73
INF   0x70
INF   0x61
INF   0x63
INF   0x65
INF  [       OK ] CborWriterTest.TstrAllocEncoding
INF  [ RUN      ] CborWriterTest.ArrayEncoding
INF  ArrayEncoding:
INF   0x98
INF   0x1d
INF  [       OK ] CborWriterTest.ArrayEncoding
INF  [ RUN      ] CborWriterTest.MapEncoding
INF  MapEncoding:
INF   0xb9
INF   0x02
INF   0x50
INF  [       OK ] CborWriterTest.MapEncoding
INF  [ RUN      ] CborWriterTest.TagEncoding
INF  TagEncoding:
INF   0xcf
INF   0xd8
INF   0x18
INF   0xd9
INF   0xd9
INF   0xf8
INF   0xda
INF   0x4f
INF   0x50
INF   0x53
INF   0x4e
INF   0xdb
INF   0x10
INF   0x00
INF   0x00
INF   0x00
INF   0x00
INF   0x00
INF   0x00
INF   0x00
INF  [       OK ] CborWriterTest.TagEncoding
INF  [ RUN      ] CborWriterTest.FalseEncoding
INF  [       OK ] CborWriterTest.FalseEncoding
INF  [ RUN      ] CborWriterTest.TrueEncoding
INF  [       OK ] CborWriterTest.TrueEncoding
INF  [ RUN      ] CborWriterTest.NullEncoding
INF  [       OK ] CborWriterTest.NullEncoding
INF  [ RUN      ] CborWriterTest.CborOutInvariants
INF  [       OK ] CborWriterTest.CborOutInvariants
INF  [ RUN      ] CborWriterTest.NullBufferForMeasurement
INF  [       OK ] CborWriterTest.NullBufferForMeasurement
INF  [ RUN      ] CborWriterTest.BufferTooSmall
INF  [       OK ] CborWriterTest.BufferTooSmall
INF  [ RUN      ] CborWriterTest.NotEnoughRemainingSpace
INF  [       OK ] CborWriterTest.NotEnoughRemainingSpace
INF  [ RUN      ] CborWriterTest.OffsetOverflow
INF  [       OK ] CborWriterTest.OffsetOverflow
INF  [ RUN      ] CborWriterTest.MeasurementOffsetOverflow
INF  [       OK ] CborWriterTest.MeasurementOffsetOverflow
INF  [==========] Done running all tests.
INF  [  PASSED  ] 23 test(s).
```

```c
// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

#include "dice/cbor_writer.h"

#include "dice/test_framework.h"
#include "pw_log/log.h"

namespace {

extern "C" {

// 배열을 한 줄로 출력하는 헬퍼 함수
void LogArray(const uint8_t* array, size_t size, const char* name) {
    PW_LOG_INFO("%s:", name);
    for (size_t i = 0; i < size; ++i) {
        PW_LOG_INFO(" 0x%02x", array[i]);
    }
}

TEST(CborWriterTest, Int1ByteEncoding) {
    const uint8_t kExpectedEncoding[] = {0, 23, 0x20, 0x37};
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteInt(0, &out);
    CborWriteInt(23, &out);
    CborWriteInt(-1, &out);
    CborWriteInt(-24, &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "Int1ByteEncoding");
}

TEST(CborWriterTest, Int2Bytes) {
    const uint8_t kExpectedEncoding[] = {24, 24, 24, 0xff, 0x38, 24, 0x38, 0xff};
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteInt(24, &out);
    CborWriteInt(0xff, &out);
    CborWriteInt(-25, &out);
    CborWriteInt(-0x100, &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "Int2Bytes");
}

TEST(CborWriterTest, Int3Bytes) {
    const uint8_t kExpectedEncoding[] = {25, 0x01, 0x00, 25, 0xff, 0xff,
                                         0x39, 0x01, 0x00, 0x39, 0xff, 0xff};
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteInt(0x100, &out);
    CborWriteInt(0xffff, &out);
    CborWriteInt(-0x101, &out);
    CborWriteInt(-0x10000, &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "Int3Bytes");
}

TEST(CborWriterTest, Int5Bytes) {
    const uint8_t kExpectedEncoding[] = {26, 0x00, 0x01, 0x00, 0x00, 26, 0xff,
                                         0xff, 0xff, 0xff, 0x3a, 0x00, 0x01, 0x00,
                                         0x00, 0x3a, 0xff, 0xff, 0xff, 0xff};
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteInt(0x10000, &out);
    CborWriteInt(0xffffffff, &out);
    CborWriteInt(-0x10001, &out);
    CborWriteInt(-0x100000000, &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "Int5Bytes");
}

TEST(CborWriterTest, Int9Bytes) {
    const uint8_t kExpectedEncoding[] = {
        27, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 27, 0x7f, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3b, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteInt(0x100000000, &out);
    CborWriteInt(INT64_MAX, &out);
    CborWriteInt(-0x100000001, &out);
    CborWriteInt(INT64_MIN, &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "Int9Bytes");
}

TEST(CborWriterTest, Uint9Bytes) {
    const uint8_t kExpectedEncoding[] = {27, 0x00, 0x00, 0x00, 0x01, 0x00,
                                         0x00, 0x00, 0x00, 27, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteUint(0x100000000, &out);
    CborWriteUint(UINT64_MAX, &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "Uint9Bytes");
}

TEST(CborWriterTest, IntByteOrder) {
    const uint8_t kExpectedEncoding[] = {
        25, 0x12, 0x34, 26, 0x12, 0x34, 0x56, 0x78, 27,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    };
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteInt(0x1234, &out);
    CborWriteInt(0x12345678, &out);
    CborWriteInt(0x123456789abcdef0, &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "IntByteOrder");
}

TEST(CborWriterTest, BstrEncoding) {
    const uint8_t kExpectedEncoding[] = {0x45, 'h', 'e', 'l', 'l', 'o'};
    const uint8_t kData[] = {'h', 'e', 'l', 'l', 'o'};
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteBstr(sizeof(kData), kData, &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "BstrEncoding");
}

TEST(CborWriterTest, BstrAllocEncoding) {
    const uint8_t kExpectedEncoding[] = {0x45, 'a', 'l', 'l', 'o', 'c'};
    const uint8_t kData[] = {'a', 'l', 'l', 'o', 'c'};
    uint8_t buffer[64];
    uint8_t* ptr;
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    ptr = CborAllocBstr(sizeof(kData), &out);
    EXPECT_NE(nullptr, ptr);
    EXPECT_FALSE(CborOutOverflowed(&out));
    memcpy(ptr, kData, sizeof(kData));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "BstrAllocEncoding");
}

TEST(CborWriterTest, TstrEncoding) {
    const uint8_t kExpectedEncoding[] = {0x65, 'w', 'o', 'r', 'l', 'd'};
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteTstr("world", &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "TstrEncoding");
}

TEST(CborWriterTest, TstrAllocEncoding) {
    const uint8_t kExpectedEncoding[] = {0x65, 's', 'p', 'a', 'c', 'e'};
    const char kStr[] = "space";
    char* ptr;
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    ptr = CborAllocTstr(strlen(kStr), &out);
    EXPECT_NE(nullptr, ptr);
    EXPECT_FALSE(CborOutOverflowed(&out));
    memcpy(ptr, kStr, sizeof(kStr));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "TstrAllocEncoding");
}

TEST(CborWriterTest, ArrayEncoding) {
    const uint8_t kExpectedEncoding[] = {0x98, 29};
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteArray(/*num_elements=*/29, &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "ArrayEncoding");
}

TEST(CborWriterTest, MapEncoding) {
    const uint8_t kExpectedEncoding[] = {0xb9, 0x02, 0x50};
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteMap(/*num_pairs=*/592, &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "MapEncoding");
}

TEST(CborWriterTest, TagEncoding) {
    const uint8_t kExpectedEncoding[] = {0xcf, 0xd8, 0x18, 0xd9, 0xd9, 0xf8, 0xda,
                                         0x4f, 0x50, 0x53, 0x4e, 0xdb, 0x10, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t buffer[64];
    CborOut out;
    CborOutInit(buffer, sizeof(buffer), &out);
    CborWriteTag(/*tag=*/15, &out);
    CborWriteTag(/*tag=*/24, &out);
    CborWriteTag(/*tag=*/0xd9f8u, &out);
    CborWriteTag(/*tag=*/0x4f50534eu, &out);
    CborWriteTag(/*tag=*/0x1000000000000000u, &out);
    EXPECT_FALSE(CborOutOverflowed(&out));
    EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));

    // 로그 출력
    LogArray(buffer, sizeof(kExpectedEncoding), "TagEncoding");
}

TEST(CborWriterTest, FalseEncoding) {
  const uint8_t kExpectedEncoding[] = {0xf4};
  uint8_t buffer[64];
  CborOut out;
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteFalse(&out);
  EXPECT_FALSE(CborOutOverflowed(&out));
  EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));
}

TEST(CborWriterTest, TrueEncoding) {
  const uint8_t kExpectedEncoding[] = {0xf5};
  uint8_t buffer[64];
  CborOut out;
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteTrue(&out);
  EXPECT_FALSE(CborOutOverflowed(&out));
  EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));
}

TEST(CborWriterTest, NullEncoding) {
  const uint8_t kExpectedEncoding[] = {0xf6};
  uint8_t buffer[64];
  CborOut out;
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteNull(&out);
  EXPECT_FALSE(CborOutOverflowed(&out));
  EXPECT_EQ(0, memcmp(buffer, kExpectedEncoding, sizeof(kExpectedEncoding)));
}

TEST(CborWriterTest, CborOutInvariants) {
  const uint8_t kData[] = {0xb2, 0x34, 0x75, 0x92, 0x52};
  uint8_t buffer[64];
  CborOut out;
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteInt(0xab34, &out);
  CborWriteBstr(sizeof(kData), kData, &out);
  EXPECT_NE(nullptr, CborAllocBstr(7, &out));
  CborWriteTstr("A string", &out);
  EXPECT_NE(nullptr, CborAllocTstr(6, &out));
  CborWriteArray(/*num_elements=*/16, &out);
  CborWriteMap(/*num_pairs=*/35, &out);
  CborWriteTag(/*tag=*/15, &out);
  CborWriteFalse(&out);
  CborWriteTrue(&out);
  CborWriteNull(&out);
  EXPECT_FALSE(CborOutOverflowed(&out));
  // Offset is the cumulative size.
  EXPECT_EQ(3 + 6 + 8 + 9 + 7 + 1 + 2 + 1 + 1 + 1 + 1u, CborOutSize(&out));
}

TEST(CborWriterTest, NullBufferForMeasurement) {
  const uint8_t kData[] = {16, 102, 246, 12, 156, 35, 84};
  CborOut out;
  CborOutInit(nullptr, 0, &out);
  CborWriteNull(&out);
  CborWriteTrue(&out);
  CborWriteFalse(&out);
  CborWriteTag(/*tag=*/15, &out);
  CborWriteMap(/*num_pairs=*/623, &out);
  CborWriteArray(/*num_elements=*/70000, &out);
  EXPECT_EQ(nullptr, CborAllocTstr(8, &out));
  CborWriteTstr("length", &out);
  EXPECT_EQ(nullptr, CborAllocBstr(1, &out));
  CborWriteBstr(sizeof(kData), kData, &out);
  CborWriteInt(-10002000, &out);
  // Measurement has occurred, but output did not.
  EXPECT_TRUE(CborOutOverflowed(&out));
  // Offset is the cumulative size.
  EXPECT_EQ(1 + 1 + 1 + 1 + 3 + 5 + 9 + 7 + 2 + 8 + 5u, CborOutSize(&out));
}

TEST(CborWriterTest, BufferTooSmall) {
  const uint8_t kData[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
  uint8_t buffer[1];
  CborOut out;
  CborOutInit(buffer, sizeof(buffer), &out);
  // Reset offset each time as it may be corrupted on failures.
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteInt(-55667788, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(sizeof(kData), kData, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  EXPECT_EQ(nullptr, CborAllocBstr(sizeof(kData), &out));
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteTstr("Buffer too small", &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  EXPECT_EQ(nullptr, CborAllocTstr(16, &out));
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteArray(/*num_elements=*/563, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteMap(/*num_pairs=*/29, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, 0, &out);
  CborWriteFalse(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, 0, &out);
  CborWriteTrue(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, 0, &out);
  CborWriteNull(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
}

TEST(CborWriterTest, NotEnoughRemainingSpace) {
  const uint8_t kData[] = {0xff, 0xee, 0xdd, 0xcc};
  uint8_t zeros[64] = {0};
  uint8_t buffer[64];
  CborOut out;
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(sizeof(buffer) - 3, zeros, &out);
  CborWriteInt(-36, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(sizeof(buffer) - 3, zeros, &out);
  CborWriteBstr(sizeof(kData), kData, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(sizeof(buffer) - 3, zeros, &out);
  EXPECT_EQ(nullptr, CborAllocBstr(sizeof(kData), &out));
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(sizeof(buffer) - 3, zeros, &out);
  CborWriteTstr("Won't fit", &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(sizeof(buffer) - 3, zeros, &out);
  EXPECT_EQ(nullptr, CborAllocTstr(4, &out));
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(sizeof(buffer) - 3, zeros, &out);
  CborWriteArray(/*num_elements=*/352, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(sizeof(buffer) - 3, zeros, &out);
  CborWriteMap(/*num_pairs=*/73, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(sizeof(buffer) - 2, zeros, &out);
  CborWriteFalse(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(sizeof(buffer) - 2, zeros, &out);
  CborWriteTrue(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(sizeof(buffer) - 2, zeros, &out);
  CborWriteNull(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
}

TEST(CborWriterTest, OffsetOverflow) {
  const uint8_t kData[] = {0xff, 0xee, 0xdd, 0xcc};
  uint8_t buffer[64];
  CborOut out;
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  CborWriteInt(0x234198adb, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  CborWriteBstr(sizeof(kData), kData, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  EXPECT_EQ(nullptr, CborAllocBstr(sizeof(kData), &out));
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  CborWriteTstr("Overflow", &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  EXPECT_EQ(nullptr, CborAllocTstr(4, &out));
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  CborWriteArray(/*num_elements=*/41, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  CborWriteMap(/*num_pairs=*/998844, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(SIZE_MAX - 9, nullptr, &out);
  CborWriteFalse(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(SIZE_MAX - 9, nullptr, &out);
  CborWriteTrue(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(buffer, sizeof(buffer), &out);
  CborWriteBstr(SIZE_MAX - 9, nullptr, &out);
  CborWriteNull(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
}

TEST(CborWriterTest, MeasurementOffsetOverflow) {
  const uint8_t kData[] = {0xf0, 0x0f, 0xca, 0xfe, 0xfe, 0xed};
  CborOut out;
  CborOutInit(nullptr, 0, &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  CborWriteInt(0x1419823646241245, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(nullptr, 0, &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  CborWriteBstr(sizeof(kData), kData, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(nullptr, 0, &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  EXPECT_EQ(nullptr, CborAllocBstr(sizeof(kData), &out));
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(nullptr, 0, &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  CborWriteTstr("Measured overflow", &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(nullptr, 0, &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  EXPECT_EQ(nullptr, CborAllocTstr(6, &out));
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(nullptr, 0, &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  CborWriteArray(/*num_elements=*/4073290018, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(nullptr, 0, &out);
  CborWriteBstr(SIZE_MAX - 10, nullptr, &out);
  CborWriteMap(/*num_pairs=*/92, &out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(nullptr, 0, &out);
  CborWriteBstr(SIZE_MAX - 9, nullptr, &out);
  CborWriteFalse(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(nullptr, 0, &out);
  CborWriteBstr(SIZE_MAX - 9, nullptr, &out);
  CborWriteTrue(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
  CborOutInit(nullptr, 0, &out);
  CborWriteBstr(SIZE_MAX - 9, nullptr, &out);
  CborWriteNull(&out);
  EXPECT_TRUE(CborOutOverflowed(&out));
}
}

}  // namespace

```
