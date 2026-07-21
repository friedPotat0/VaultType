using System.Buffers.Binary;

namespace VaultType.Vault.Crypto;

// Pure-managed Argon2id (RFC 9106) + the BLAKE2b (RFC 7693) it needs. Lives in VaultType's own
// assembly so it loads under a WDAC "Microsoft signing level" policy that blocks third-party DLLs -
// the reason the BouncyCastle dependency was removed. Verified against the RFC 9106 §5.3 known-answer
// test vector (see CryptoSelfTest). Only Argon2id (type 2), version 0x13, is implemented - the one
// variant Bitwarden uses.
internal static class Argon2id
{
    private const int BlockSize = 1024;              // bytes
    private const int Words = BlockSize / 8;         // 128 uint64 per block

    // Full Argon2id. secret/associatedData are optional (Bitwarden passes neither).
    public static byte[] Hash(
        ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
        int parallelism, int memoryKiB, int iterations, int outLen,
        ReadOnlySpan<byte> secret = default, ReadOnlySpan<byte> associatedData = default)
    {
        uint p = (uint)parallelism, m = (uint)memoryKiB, t = (uint)iterations, T = (uint)outLen;

        // H0 = BLAKE2b-512 over all parameters and inputs (RFC 9106 §3.2).
        var pre = new Blake2b(64);
        var le = new byte[4];
        void U32(uint v) { BinaryPrimitives.WriteUInt32LittleEndian(le, v); pre.Update(le); }
        void Field(ReadOnlySpan<byte> b) { U32((uint)b.Length); pre.Update(b); }
        U32(p); U32(T); U32(m); U32(t); U32(0x13); U32(2 /* Argon2id */);
        Field(password); Field(salt); Field(secret); Field(associatedData);
        byte[] h0 = pre.Finish();

        // Memory layout.
        uint mPrime = 4 * p * (m / (4 * p));         // round down to a multiple of 4p
        uint laneLen = mPrime / p;                   // columns per lane (q)
        uint segLen = laneLen / 4;
        var B = new ulong[mPrime][];
        for (uint i = 0; i < mPrime; i++) B[i] = new ulong[Words];

        // First two columns of each lane from H'.
        Span<byte> seedBuf = stackalloc byte[72];    // h0(64) + LE32(col) + LE32(lane)
        h0.CopyTo(seedBuf);
        for (uint lane = 0; lane < p; lane++)
        {
            for (uint col = 0; col < 2; col++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(seedBuf.Slice(64, 4), col);
                BinaryPrimitives.WriteUInt32LittleEndian(seedBuf.Slice(68, 4), lane);
                LoadBlock(B[lane * laneLen + col], Hprime(BlockSize, seedBuf));
            }
        }

        // Fill passes.
        var address = new ulong[Words];
        var input = new ulong[Words];
        var zero = new ulong[Words];
        var tmp = new ulong[Words];
        for (uint pass = 0; pass < t; pass++)
        {
            for (uint slice = 0; slice < 4; slice++)
            {
                for (uint lane = 0; lane < p; lane++)
                {
                    // Argon2id: data-independent addressing for the first two slices of pass 0.
                    bool dataIndependent = pass == 0 && slice < 2;
                    if (dataIndependent)
                    {
                        Array.Clear(input);
                        input[0] = pass; input[1] = lane; input[2] = slice;
                        input[3] = mPrime; input[4] = t; input[5] = 2; // type Argon2id
                    }

                    uint startIndex = (pass == 0 && slice == 0) ? 2u : 0u;
                    uint addrCounter = 0;
                    for (uint index = startIndex; index < segLen; index++)
                    {
                        uint col = slice * segLen + index;
                        uint curr = lane * laneLen + col;
                        uint prevCol = col == 0 ? laneLen - 1 : col - 1;
                        ulong[] prev = B[lane * laneLen + prevCol];

                        // pseudo-random J1/J2
                        ulong pseudoRand;
                        if (dataIndependent)
                        {
                            if (index % Words == 0)
                            {
                                addrCounter++;
                                input[6] = addrCounter;
                                FillBlock(zero, input, tmp, false);
                                FillBlock(zero, tmp, address, false);
                            }
                            pseudoRand = address[index % Words];
                        }
                        else
                        {
                            pseudoRand = prev[0];
                        }

                        uint j1 = (uint)(pseudoRand & 0xFFFFFFFF);
                        uint j2 = (uint)(pseudoRand >> 32);
                        uint refLane = (pass == 0 && slice == 0) ? lane : j2 % p;

                        // reference area size (RFC 9106 §3.4.1.1)
                        uint refAreaSize;
                        bool sameLane = refLane == lane;
                        if (pass == 0)
                            refAreaSize = slice == 0 ? index - 1
                                : sameLane ? slice * segLen + index - 1
                                : slice * segLen - (index == 0 ? 1u : 0u);
                        else
                            refAreaSize = sameLane ? laneLen - segLen + index - 1
                                : laneLen - segLen - (index == 0 ? 1u : 0u);

                        // map J1 into [0, refAreaSize)
                        ulong rel = j1;
                        rel = (rel * rel) >> 32;
                        rel = refAreaSize - 1 - ((refAreaSize * rel) >> 32);
                        uint startPos = (pass != 0) ? (slice == 3 ? 0u : (slice + 1) * segLen) : 0u;
                        uint refIndex = (uint)((startPos + rel) % laneLen);

                        ulong[] refBlock = B[refLane * laneLen + refIndex];
                        // v1.3: XOR into the existing block on passes after the first.
                        FillBlock(prev, refBlock, B[curr], withXor: pass != 0);
                    }
                }
            }
        }

        // C = XOR of the last column of every lane; tag = H'(C).
        var final = new ulong[Words];
        for (uint lane = 0; lane < p; lane++)
        {
            ulong[] last = B[lane * laneLen + (laneLen - 1)];
            for (int i = 0; i < Words; i++) final[i] ^= last[i];
        }
        byte[] finalBytes = StoreBlock(final);
        return Hprime(outLen, finalBytes);
    }

    // --- Argon2 compression function G / fill_block (RFC 9106 §3.6) ---

    private static void FillBlock(ulong[] prev, ulong[] refBlock, ulong[] next, bool withXor)
    {
        Span<ulong> r = stackalloc ulong[Words];
        Span<ulong> z = stackalloc ulong[Words];
        for (int i = 0; i < Words; i++) { r[i] = prev[i] ^ refBlock[i]; z[i] = r[i]; }

        // The block is an 8x8 matrix of 16-byte registers (2 words each): word = 16*row + 2*reg + {0,1}.
        Span<int> idx = stackalloc int[16];
        // rows: 16 contiguous words each
        for (int row = 0; row < 8; row++)
        {
            for (int j = 0; j < 16; j++) idx[j] = 16 * row + j;
            Round(z, idx);
        }
        // columns: register `col` across all 8 rows -> word pairs 16*k + 2*col + {0,1}
        for (int col = 0; col < 8; col++)
        {
            for (int k = 0; k < 8; k++) { idx[2 * k] = 16 * k + 2 * col; idx[2 * k + 1] = 16 * k + 2 * col + 1; }
            Round(z, idx);
        }

        if (withXor)
            for (int i = 0; i < Words; i++) next[i] ^= r[i] ^ z[i];
        else
            for (int i = 0; i < Words; i++) next[i] = r[i] ^ z[i];
    }

    // Apply the BLAKE2 round to the 16 words named by idx[0..15].
    private static void Round(Span<ulong> b, Span<int> idx)
    {
        Mix(b, idx[0], idx[4], idx[8], idx[12]);
        Mix(b, idx[1], idx[5], idx[9], idx[13]);
        Mix(b, idx[2], idx[6], idx[10], idx[14]);
        Mix(b, idx[3], idx[7], idx[11], idx[15]);
        Mix(b, idx[0], idx[5], idx[10], idx[15]);
        Mix(b, idx[1], idx[6], idx[11], idx[12]);
        Mix(b, idx[2], idx[7], idx[8], idx[13]);
        Mix(b, idx[3], idx[4], idx[9], idx[14]);
    }

    // Argon2's modified BLAKE2 mixing (fBlaMka: adds 2*low32(a)*low32(b)).
    private static void Mix(Span<ulong> v, int a, int b, int c, int d)
    {
        v[a] = v[a] + v[b] + 2 * (v[a] & 0xFFFFFFFF) * (v[b] & 0xFFFFFFFF);
        v[d] = ulong.RotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d] + 2 * (v[c] & 0xFFFFFFFF) * (v[d] & 0xFFFFFFFF);
        v[b] = ulong.RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + 2 * (v[a] & 0xFFFFFFFF) * (v[b] & 0xFFFFFFFF);
        v[d] = ulong.RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d] + 2 * (v[c] & 0xFFFFFFFF) * (v[d] & 0xFFFFFFFF);
        v[b] = ulong.RotateRight(v[b] ^ v[c], 63);
    }

    private static void LoadBlock(ulong[] dst, byte[] src)
    {
        for (int i = 0; i < Words; i++) dst[i] = BinaryPrimitives.ReadUInt64LittleEndian(src.AsSpan(i * 8, 8));
    }

    private static byte[] StoreBlock(ulong[] src)
    {
        var outp = new byte[BlockSize];
        for (int i = 0; i < Words; i++) BinaryPrimitives.WriteUInt64LittleEndian(outp.AsSpan(i * 8, 8), src[i]);
        return outp;
    }

    // Variable-length hash H' (RFC 9106 §3.3): BLAKE2b for T<=64, else a 32-byte-per-step chain.
    private static byte[] Hprime(int outLen, ReadOnlySpan<byte> input)
    {
        Span<byte> lenPrefix = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lenPrefix, (uint)outLen);

        if (outLen <= 64)
        {
            var h = new Blake2b(outLen);
            h.Update(lenPrefix);
            h.Update(input);
            return h.Finish();
        }

        var result = new byte[outLen];
        var v = new Blake2b(64);
        v.Update(lenPrefix);
        v.Update(input);
        byte[] block = v.Finish();               // V1
        block.AsSpan(0, 32).CopyTo(result);
        int pos = 32;
        // remaining full 32-byte chunks
        while (outLen - pos > 64)
        {
            block = new Blake2b(64).UpdateFinish(block);
            block.AsSpan(0, 32).CopyTo(result.AsSpan(pos));
            pos += 32;
        }
        // last chunk of size outLen-pos (1..64)
        byte[] lastBlock = new Blake2b(outLen - pos).UpdateFinish(block);
        lastBlock.CopyTo(result.AsSpan(pos));
        return result;
    }
}

// BLAKE2b (RFC 7693), unkeyed, output length 1..64. Only what Argon2 needs.
internal sealed class Blake2b
{
    private static readonly ulong[] IV =
    {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
    };

    private static readonly byte[][] Sigma =
    {
        new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        new byte[]{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
        new byte[]{11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
        new byte[]{7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
        new byte[]{9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
        new byte[]{2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
        new byte[]{12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
        new byte[]{13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
        new byte[]{6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
        new byte[]{10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
        new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        new byte[]{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
    };

    private readonly ulong[] _h = new ulong[8];
    private readonly byte[] _buf = new byte[128];
    private int _bufLen;
    private ulong _t0, _t1;
    private readonly int _outLen;

    public Blake2b(int outLen)
    {
        if (outLen < 1 || outLen > 64) throw new ArgumentOutOfRangeException(nameof(outLen));
        _outLen = outLen;
        for (int i = 0; i < 8; i++) _h[i] = IV[i];
        _h[0] ^= 0x01010000UL ^ (ulong)(uint)outLen;   // no key
    }

    // Convenience: hash a single buffer in one shot.
    public byte[] UpdateFinish(ReadOnlySpan<byte> data) { Update(data); return Finish(); }

    public void Update(ReadOnlySpan<byte> data)
    {
        int i = 0;
        while (i < data.Length)
        {
            if (_bufLen == 128)   // full block and more data is coming -> not the last block
            {
                IncrementCounter(128);
                Compress(false);
                _bufLen = 0;
            }
            int take = Math.Min(128 - _bufLen, data.Length - i);
            data.Slice(i, take).CopyTo(_buf.AsSpan(_bufLen));
            _bufLen += take;
            i += take;
        }
    }

    public byte[] Finish()
    {
        IncrementCounter((ulong)_bufLen);
        _buf.AsSpan(_bufLen).Clear();     // zero-pad
        Compress(true);
        var outp = new byte[_outLen];
        Span<byte> full = stackalloc byte[64];
        for (int i = 0; i < 8; i++) BinaryPrimitives.WriteUInt64LittleEndian(full.Slice(i * 8, 8), _h[i]);
        full[.._outLen].CopyTo(outp);
        return outp;
    }

    private void IncrementCounter(ulong n)
    {
        _t0 += n;
        if (_t0 < n) _t1++;
    }

    private void Compress(bool last)
    {
        Span<ulong> m = stackalloc ulong[16];
        for (int i = 0; i < 16; i++) m[i] = BinaryPrimitives.ReadUInt64LittleEndian(_buf.AsSpan(i * 8, 8));

        Span<ulong> v = stackalloc ulong[16];
        for (int i = 0; i < 8; i++) { v[i] = _h[i]; v[i + 8] = IV[i]; }
        v[12] ^= _t0;
        v[13] ^= _t1;
        if (last) v[14] ^= 0xFFFFFFFFFFFFFFFFUL;

        for (int round = 0; round < 12; round++)
        {
            byte[] s = Sigma[round];
            G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for (int i = 0; i < 8; i++) _h[i] ^= v[i] ^ v[i + 8];
    }

    private static void G(Span<ulong> v, int a, int b, int c, int d, ulong x, ulong y)
    {
        v[a] = v[a] + v[b] + x;
        v[d] = ulong.RotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = ulong.RotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = ulong.RotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = ulong.RotateRight(v[b] ^ v[c], 63);
    }
}
