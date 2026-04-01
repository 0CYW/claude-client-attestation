const PRIME64_1 = 0x9e3779b185ebca87n;
const PRIME64_2 = 0xc2b2ae3d27d4eb4fn;
const PRIME64_3 = 0x165667b19e3779f9n;
const PRIME64_4 = 0x85ebca77c2b2ae63n;
const PRIME64_5 = 0x27d4eb2f165667c5n;
const MASK64 = 0xffffffffffffffffn;

const CCH_XXH64_SEED = 0x6e52736ac806831en;

function rotl64(x: bigint, r: bigint): bigint {
  return ((x << r) | (x >> (64n - r))) & MASK64;
}

function readU32LE(buf: Buffer, offset: number): bigint {
  return BigInt(
    (buf[offset]! |
      (buf[offset + 1]! << 8) |
      (buf[offset + 2]! << 16) |
      (buf[offset + 3]! << 24)) >>>
      0,
  );
}

function readU64LE(buf: Buffer, offset: number): bigint {
  const lo = readU32LE(buf, offset);
  const hi = readU32LE(buf, offset + 4);
  return (hi << 32n) | lo;
}

function round64(acc: bigint, lane: bigint): bigint {
  const mixed = (acc + ((lane * PRIME64_2) & MASK64)) & MASK64;
  return (rotl64(mixed, 31n) * PRIME64_1) & MASK64;
}

function mergeRound64(acc: bigint, val: bigint): bigint {
  let out = (acc ^ round64(0n, val)) & MASK64;
  out = (out * PRIME64_1 + PRIME64_4) & MASK64;
  return out;
}

function avalanche64(h: bigint): bigint {
  let out = h & MASK64;
  out ^= out >> 33n;
  out = (out * PRIME64_2) & MASK64;
  out ^= out >> 29n;
  out = (out * PRIME64_3) & MASK64;
  out ^= out >> 32n;
  return out & MASK64;
}

function xxh64(input: Buffer, seed: bigint = 0n): bigint {
  const len = input.length;
  let p = 0;
  let h64: bigint;

  if (len >= 32) {
    let v1 = (seed + PRIME64_1 + PRIME64_2) & MASK64;
    let v2 = (seed + PRIME64_2) & MASK64;
    let v3 = seed & MASK64;
    let v4 = (seed - PRIME64_1) & MASK64;

    const limit = len - 32;
    while (p <= limit) {
      v1 = round64(v1, readU64LE(input, p));
      p += 8;
      v2 = round64(v2, readU64LE(input, p));
      p += 8;
      v3 = round64(v3, readU64LE(input, p));
      p += 8;
      v4 = round64(v4, readU64LE(input, p));
      p += 8;
    }

    h64 =
      (rotl64(v1, 1n) + rotl64(v2, 7n) + rotl64(v3, 12n) + rotl64(v4, 18n)) &
      MASK64;
    h64 = mergeRound64(h64, v1);
    h64 = mergeRound64(h64, v2);
    h64 = mergeRound64(h64, v3);
    h64 = mergeRound64(h64, v4);
  } else {
    h64 = (seed + PRIME64_5) & MASK64;
  }

  h64 = (h64 + BigInt(len)) & MASK64;

  while (p + 8 <= len) {
    const k1 = round64(0n, readU64LE(input, p));
    p += 8;
    h64 ^= k1;
    h64 = (rotl64(h64, 27n) * PRIME64_1 + PRIME64_4) & MASK64;
  }

  if (p + 4 <= len) {
    h64 ^= (readU32LE(input, p) * PRIME64_1) & MASK64;
    p += 4;
    h64 = (rotl64(h64, 23n) * PRIME64_2 + PRIME64_3) & MASK64;
  }

  while (p < len) {
    h64 ^= (BigInt(input[p]!) * PRIME64_5) & MASK64;
    p += 1;
    h64 = (rotl64(h64, 11n) * PRIME64_1) & MASK64;
  }

  return avalanche64(h64);
}

export function patchRequestBody(input: string): string {
  const idx = input.indexOf("cch=00000");
  if (idx < 0) {
    throw new Error("Attestation placeholder was not found in input");
  }

  const bodyBytes = Buffer.from(input, "utf8");
  const digest = xxh64(bodyBytes, CCH_XXH64_SEED);
  const token = (digest & 0xfffffn).toString(16).padStart(5, "0");
  const patchedBodyJson =
    input.slice(0, idx + 4) + token + input.slice(idx + 9);

  return patchedBodyJson;
}
