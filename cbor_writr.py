import struct

class CborOut:
    def __init__(self, buffer_size):
        self.buffer = bytearray(buffer_size)
        self.buffer_size = buffer_size
        self.cursor = 0

    def CborOutSize(self):
        return self.cursor

    def CborOutOverflowed(self):
        return self.cursor == -1 or self.cursor > self.buffer_size

    def CborWriteWouldOverflowCursor(self, size):
        return size > 0xFFFFFFFFFFFFFFFF - self.cursor

    def CborWriteFitsInBuffer(self, size):
        return self.cursor <= self.buffer_size and size <= self.buffer_size - self.cursor

    def CborWriteType(self, type, val):
        if val <= 23:
            size = 1
        elif val <= 0xff:
            size = 2
        elif val <= 0xffff:
            size = 3
        elif val <= 0xffffffff:
            size = 5
        else:
            size = 9

        if self.CborWriteWouldOverflowCursor(size):
            self.cursor = -1
            return

        if self.CborWriteFitsInBuffer(size):
            if size == 1:
                self.buffer[self.cursor] = (type << 5) | val
            elif size == 2:
                self.buffer[self.cursor:self.cursor+2] = struct.pack("BB", (type << 5) | 24, val)
            elif size == 3:
                self.buffer[self.cursor:self.cursor+3] = struct.pack("!BH", (type << 5) | 25, val)
            elif size == 5:
                self.buffer[self.cursor:self.cursor+5] = struct.pack("!BI", (type << 5) | 26, val)
            elif size == 9:
                self.buffer[self.cursor:self.cursor+9] = struct.pack("!BQ", (type << 5) | 27, val)

        self.cursor += size

    def CborAllocStr(self, type, data_size):
        self.CborWriteType(type, data_size)
        if self.CborWriteWouldOverflowCursor(data_size) or not self.CborWriteFitsInBuffer(data_size):
            return None
        ptr = self.buffer[self.cursor:self.cursor+data_size]
        self.cursor += data_size
        return ptr

    def CborWriteStr(self, type, data_size, data):
        ptr = self.CborAllocStr(type, data_size)
        if ptr is not None and data_size:
            ptr[:] = data

    def CborWriteInt(self, val):
        if val < 0:
            self.CborWriteType(1, -1 - val)
        else:
            self.CborWriteType(0, val)

    def CborWriteUint(self, val):
        self.CborWriteType(0, val)

    def CborWriteBstr(self, data):
        self.CborWriteStr(2, len(data), data)

    def CborAllocBstr(self, data_size):
        return self.CborAllocStr(2, data_size)

    def CborWriteTstr(self, string):
        data = string.encode('utf-8')
        self.CborWriteStr(3, len(data), data)

    def CborAllocTstr(self, size):
        return self.CborAllocStr(3, size)

    def CborWriteArray(self, num_elements):
        self.CborWriteType(4, num_elements)

    def CborWriteMap(self, num_pairs):
        self.CborWriteType(5, num_pairs)

    def CborWriteTag(self, tag):
        self.CborWriteType(6, tag)

    def CborWriteFalse(self):
        self.CborWriteType(7, 20)

    def CborWriteTrue(self):
        self.CborWriteType(7, 21)

    def CborWriteNull(self):
        self.CborWriteType(7, 22)

# Example usage:
cbor_out = CborOut(256)
cbor_out.CborWriteInt(123)
cbor_out.CborWriteUint(456)
cbor_out.CborWriteTstr("Hello, CBOR")
cbor_out.CborWriteFalse()

print(cbor_out.buffer[:cbor_out.CborOutSize()])
