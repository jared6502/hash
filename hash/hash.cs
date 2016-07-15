using System;

namespace Hash
{
    public static class HashFunctions
    {
        public static class MurmurHash
        {
            public static class MurmurHash3
            {
                private static UInt32 rotl32(UInt32 x, sbyte r)
                {
                    return (x << r) | (x >> (32 - r));
                }

                private static UInt64 rotl64(UInt64 x, sbyte r)
                {
                    return (x << r) | (x >> (64 - r));
                }

                //-----------------------------------------------------------------------------
                // Finalization mix - force all bits of a hash block to avalanche

                private static UInt32 fmix32(UInt32 h)
                {
                    h ^= h >> 16;
                    h *= 0x85ebca6b;
                    h ^= h >> 13;
                    h *= 0xc2b2ae35;
                    h ^= h >> 16;

                    return h;
                }

                //----------

                private static UInt64 fmix64(UInt64 k)
                {
                    k ^= k >> 33;
                    k *= 0xff51afd7ed558ccd;
                    k ^= k >> 33;
                    k *= 0xc4ceb9fe1a85ec53;
                    k ^= k >> 33;

                    return k;
                }

                //-----------------------------------------------------------------------------

                public static UInt32[] MurmurHash3_x86_32(byte[] key, int len, UInt32 seed)
                {
                    byte[] data = key;
                    int nblocks = len / 4;

                    UInt32 h1 = seed;
                    UInt32 k1;

                    const UInt32 c1 = 0xcc9e2d51;
                    const UInt32 c2 = 0x1b873593;

                    //----------
                    // body

                    UInt32[] blocks = BytesToUInt32(data);

                    for (int i = 0; i < blocks.Length; i++)
                    {
                        k1 = blocks[i];

                        k1 *= c1;
                        k1 = rotl32(k1, 15);
                        k1 *= c2;

                        h1 ^= k1;
                        h1 = rotl32(h1, 13);
                        h1 = h1 * 5 + 0xe6546b64;
                    }

                    //----------
                    // tail

                    byte[] tail = GetTail32(len, data);

                    k1 = 0;

                    switch (tail.Length)
                    {
                        case 3:
                            k1 ^= (UInt32)(tail[2] << 16);
                            goto case 2;
                        case 2:
                            k1 ^= (UInt32)(tail[1] << 8);
                            goto case 1;
                        case 1:
                            k1 ^= tail[0];
                            k1 *= c1;
                            k1 = rotl32(k1, 15);
                            k1 *= c2; h1 ^= k1;
                            break;
                    };

                    //----------
                    // finalization

                    h1 ^= (UInt32)(len);

                    h1 = fmix32(h1);

                    UInt32[] output = new UInt32[1];
                    output[0] = h1;
                    return output;
                }

                //-----------------------------------------------------------------------------

                public static UInt32[] MurmurHash3_x86_128(byte[] key, int len, UInt32 seed)
                {
                    byte[] data = key;
                    int nblocks = len / 16;

                    UInt32 h1 = seed;
                    UInt32 h2 = seed;
                    UInt32 h3 = seed;
                    UInt32 h4 = seed;

                    UInt32 k1;
                    UInt32 k2;
                    UInt32 k3;
                    UInt32 k4;

                    const UInt32 c1 = 0x239b961b;
                    const UInt32 c2 = 0xab0e9789;
                    const UInt32 c3 = 0x38b34ae5;
                    const UInt32 c4 = 0xa1e38b93;

                    //----------
                    // body

                    UInt32[] blocks = BytesToUInt32(data);

                    for (int i = 0; i < nblocks; i++)
                    {
                        k1 = blocks[(i * 4) + 0];
                        k2 = blocks[(i * 4) + 1];
                        k3 = blocks[(i * 4) + 2];
                        k4 = blocks[(i * 4) + 3];

                        k1 *= c1;
                        k1 = rotl32(k1, 15);
                        k1 *= c2;
                        h1 ^= k1;

                        h1 = rotl32(h1, 19);
                        h1 += h2;
                        h1 = h1 * 5 + 0x561ccd1b;

                        k2 *= c2;
                        k2 = rotl32(k2, 16);
                        k2 *= c3;
                        h2 ^= k2;

                        h2 = rotl32(h2, 17);
                        h2 += h3;
                        h2 = h2 * 5 + 0x0bcaa747;

                        k3 *= c3;
                        k3 = rotl32(k3, 17);
                        k3 *= c4;
                        h3 ^= k3;

                        h3 = rotl32(h3, 15);
                        h3 += h4;
                        h3 = h3 * 5 + 0x96cd1c35;

                        k4 *= c4; k4 = rotl32(k4, 18); k4 *= c1; h4 ^= k4;

                        h4 = rotl32(h4, 13); h4 += h1; h4 = h4 * 5 + 0x32ac3b17;
                    }

                    //----------
                    // tail

                    byte[] tail = GetTail128(len, data);

                    k1 = 0;
                    k2 = 0;
                    k3 = 0;
                    k4 = 0;

                    switch (tail.Length)
                    {
                        case 15:
                            k4 ^= (UInt32)(tail[14] << 16);
                            goto case 14;
                        case 14:
                            k4 ^= (UInt32)(tail[13] << 8);
                            goto case 13;
                        case 13:
                            k4 ^= (UInt32)(tail[12] << 0);
                            k4 *= c4;
                            k4 = rotl32(k4, 18);
                            k4 *= c1;
                            h4 ^= k4;
                            goto case 12;
                        case 12:
                            k3 ^= (UInt32)(tail[11] << 24);
                            goto case 11;
                        case 11:
                            k3 ^= (UInt32)(tail[10] << 16);
                            goto case 10;
                        case 10:
                            k3 ^= (UInt32)(tail[9] << 8);
                            goto case 9;
                        case 9:
                            k3 ^= (UInt32)(tail[8] << 0);
                            k3 *= c3;
                            k3 = rotl32(k3, 17);
                            k3 *= c4;
                            h3 ^= k3;
                            goto case 8;
                        case 8:
                            k2 ^= (UInt32)(tail[7] << 24);
                            goto case 7;
                        case 7:
                            k2 ^= (UInt32)(tail[6] << 16);
                            goto case 6;
                        case 6:
                            k2 ^= (UInt32)(tail[5] << 8);
                            goto case 5;
                        case 5:
                            k2 ^= (UInt32)(tail[4] << 0);
                            k2 *= c2;
                            k2 = rotl32(k2, 16);
                            k2 *= c3;
                            h2 ^= k2;
                            goto case 4;
                        case 4:
                            k1 ^= (UInt32)(tail[3] << 24);
                            goto case 3;
                        case 3:
                            k1 ^= (UInt32)(tail[2] << 16);
                            goto case 2;
                        case 2:
                            k1 ^= (UInt32)(tail[1] << 8);
                            goto case 1;
                        case 1:
                            k1 ^= (UInt32)(tail[0] << 0);
                            k1 *= c1;
                            k1 = rotl32(k1, 15);
                            k1 *= c2;
                            h1 ^= k1;
                            break;
                    };

                    //----------
                    // finalization

                    h1 ^= (UInt32)(len);
                    h2 ^= (UInt32)(len);
                    h3 ^= (UInt32)(len);
                    h4 ^= (UInt32)(len);

                    h1 += h2;
                    h1 += h3;
                    h1 += h4;
                    h2 += h1;
                    h3 += h1;
                    h4 += h1;

                    h1 = fmix32(h1);
                    h2 = fmix32(h2);
                    h3 = fmix32(h3);
                    h4 = fmix32(h4);

                    h1 += h2;
                    h1 += h3;
                    h1 += h4;
                    h2 += h1;
                    h3 += h1;
                    h4 += h1;

                    UInt32[] output = new UInt32[4];

                    output[0] = h1;
                    output[1] = h2;
                    output[2] = h3;
                    output[3] = h4;

                    return output;
                }

                //-----------------------------------------------------------------------------

                public static UInt64[] MurmurHash3_x64_128(byte[] key, int len, UInt32 seed)
                {
                    byte[] data = key;
                    int nblocks = len / 16;

                    UInt64 h1 = seed;
                    UInt64 h2 = seed;

                    UInt64 k1;
                    UInt64 k2;

                    const UInt64 c1 = 0x87c37b91114253d5UL;
                    const UInt64 c2 = 0x4cf5ad432745937fUL;

                    //----------
                    // body

                    UInt64[] blocks = BytesToUInt64(data);

                    for (int i = 0; i < nblocks; i++)
                    {
                        k1 = blocks[(i * 2) + 0];
                        k2 = blocks[(i * 2) + 1];

                        k1 *= c1;
                        k1 = rotl64(k1, 31);
                        k1 *= c2;
                        h1 ^= k1;

                        h1 = rotl64(h1, 27);
                        h1 += h2;
                        h1 = h1 * 5UL + 0x52dce729UL;

                        k2 *= c2;
                        k2 = rotl64(k2, 33);
                        k2 *= c1;
                        h2 ^= k2;

                        h2 = rotl64(h2, 31);
                        h2 += h1;
                        h2 = h2 * 5UL + 0x38495ab5UL;
                    }

                    //----------
                    // tail

                    byte[] tail = GetTail128(len, data);

                    k1 = 0;
                    k2 = 0;

                    switch (tail.Length)
                    {
                        case 15:
                            k2 ^= (UInt64)tail[14] << 48;
                            goto case 14;
                        case 14:
                            k2 ^= (UInt64)tail[13] << 40;
                            goto case 13;
                        case 13:
                            k2 ^= (UInt64)tail[12] << 32;
                            goto case 12;
                        case 12:
                            k2 ^= (UInt64)tail[11] << 24;
                            goto case 11;
                        case 11:
                            k2 ^= (UInt64)tail[10] << 16;
                            goto case 10;
                        case 10:
                            k2 ^= (UInt64)tail[9] << 8;
                            goto case 9;
                        case 9:
                            k2 ^= (UInt64)tail[8] << 0;
                            k2 *= c2;
                            k2 = rotl64(k2, 33);
                            k2 *= c1;
                            h2 ^= k2;
                            goto case 8;
                        case 8:
                            k1 ^= (UInt64)tail[7] << 56;
                            goto case 7;
                        case 7:
                            k1 ^= (UInt64)tail[6] << 48;
                            goto case 6;
                        case 6:
                            k1 ^= (UInt64)tail[5] << 40;
                            goto case 5;
                        case 5:
                            k1 ^= (UInt64)tail[4] << 32;
                            goto case 4;
                        case 4:
                            k1 ^= (UInt64)tail[3] << 24;
                            goto case 3;
                        case 3:
                            k1 ^= (UInt64)tail[2] << 16;
                            goto case 2;
                        case 2:
                            k1 ^= (UInt64)tail[1] << 8;
                            goto case 1;
                        case 1:
                            k1 ^= (UInt64)tail[0] << 0;
                            k1 *= c1;
                            k1 = rotl64(k1, 31);
                            k1 *= c2;
                            h1 ^= k1;
                            break;
                    };

                    //----------
                    // finalization

                    h1 ^= (UInt64)len;
                    h2 ^= (UInt64)len;

                    h1 += h2;
                    h2 += h1;

                    h1 = fmix64(h1);
                    h2 = fmix64(h2);

                    h1 += h2;
                    h2 += h1;

                    UInt64[] output = new UInt64[2];
                    output[0] = h1;
                    output[1] = h2;

                    return output;
                }

                //-----------------------------------------------------------------------------

                private static UInt32[] BytesToUInt32(byte[] input)
                {
                    int len = (input.Length >> 2);

                    UInt32[] output = new UInt32[len];

                    int index;
                    UInt32 temp;

                    for (int i = 0; i < len; i++)
                    {
                        index = (i << 2);
                        temp = 0;
                        if (index < input.Length) temp += input[index];
                        if ((index + 1) < input.Length) temp += (UInt32)(input[index + 1] << 8);
                        if ((index + 2) < input.Length) temp += (UInt32)(input[index + 2] << 16);
                        if ((index + 3) < input.Length) temp += (UInt32)(input[index + 3] << 24);

                        output[i] = temp;
                    }

                    return output;
                }

                private static UInt64[] BytesToUInt64(byte[] input)
                {
                    int len = (input.Length >> 3);

                    UInt64[] output = new UInt64[len];

                    int index;
                    UInt64 temp;

                    for (int i = 0; i < len; i++)
                    {
                        index = (i << 3);
                        temp = 0;
                        if ((index + 0) < input.Length) temp += ((UInt64)input[index + 0]) << 0;
                        if ((index + 1) < input.Length) temp += ((UInt64)input[index + 1]) << 8;
                        if ((index + 2) < input.Length) temp += ((UInt64)input[index + 2]) << 16;
                        if ((index + 3) < input.Length) temp += ((UInt64)input[index + 3]) << 24;
                        if ((index + 4) < input.Length) temp += ((UInt64)input[index + 4]) << 32;
                        if ((index + 5) < input.Length) temp += ((UInt64)input[index + 5]) << 40;
                        if ((index + 6) < input.Length) temp += ((UInt64)input[index + 6]) << 48;
                        if ((index + 7) < input.Length) temp += ((UInt64)input[index + 7]) << 56;

                        output[i] = temp;
                    }

                    return output;
                }

                private static byte[] GetTail32(int len, byte[] data)
                {
                    return GetTail(len - (len % 4), len % 4, data);
                }

                private static byte[] GetTail128(int len, byte[] data)
                {
                    return GetTail(len - (len % 16), len % 16, data);
                }

                private static byte[] GetTail(int start, int count, byte[] data)
                {
                    byte[] tail = new byte[count];

                    for (int i = 0; i < tail.Length; i++)
                    {
                        tail[i] = data[start + i];
                    }

                    return tail;
                }
            }
        }

        public static class Crc
        {
            static UInt32 Crc32(byte[] message)
            {
                int i, j;
                UInt32 b, crc, mask;

                i = 0;
                crc = 0xFFFFFFFF;
                while (i < message.Length)
                {
                    b = message[i];
                    crc = crc ^ b;
                    for (j = 7; j >= 0; j--)
                    {
                        mask = (UInt32)(-(crc & 1));
                        crc = (crc >> 1) ^ (0xEDB88320 & mask);
                    }
                    i = i + 1;
                }
                return ~crc;
            }
        }
    }
}
