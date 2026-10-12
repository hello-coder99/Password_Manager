/**
 * Cryptographically secure password generator with unbiased rejection sampling
 * and entropy-based password strength estimation.
 * Never uses Math.random() or modulo-biased character selection.
 */

const CHARSETS = Object.freeze({
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  numbers: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.<>/?~",
});

const AMBIGUOUS_CHARS = new Set(["0", "O", "o", "1", "l", "I", "|", "`", "'", "\""]);

/**
 * Fill a Uint32Array with cryptographically secure random integers via Web Crypto API.
 * @param {number} count
 * @returns {Uint32Array}
 */
function getRandomUint32Values(count) {
  const buf = new Uint32Array(count);
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === "function") {
    globalThis.crypto.getRandomValues(buf);
    return buf;
  }
  throw new Error("Cryptographically secure random number generator is unavailable.");
}

/**
 * Select a uniform random integer in [0, maxExclusive) using rejection sampling
 * to eliminate modulo bias.
 * @param {number} maxExclusive
 * @returns {number}
 */
export function uniformRandomIndex(maxExclusive) {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
    throw new Error("maxExclusive must be a positive integer.");
  }
  if (maxExclusive === 1) {
    return 0;
  }

  const maxUint32PlusOne = 0x100000000; // 2^32
  const limit = maxUint32PlusOne - (maxUint32PlusOne % maxExclusive);

  while (true) {
    const [candidate] = getRandomUint32Values(1);
    if (candidate < limit) {
      return candidate % maxExclusive;
    }
  }
}

/**
 * Cryptographically secure Fisher-Yates shuffle in-place.
 * @param {string[]} array
 * @returns {string[]}
 */
function secureShuffle(array) {
  for (let i = array.length - 1; i > 0; i -= 1) {
    const j = uniformRandomIndex(i + 1);
    const tmp = array[i];
    array[i] = array[j];
    array[j] = tmp;
  }
  return array;
}

/**
 * Filter out ambiguous characters when requested.
 * @param {string} pool
 * @param {boolean} excludeAmbiguous
 * @returns {string}
 */
function filterCharset(pool, excludeAmbiguous) {
  if (!excludeAmbiguous) {
    return pool;
  }
  return Array.from(pool)
    .filter((ch) => !AMBIGUOUS_CHARS.has(ch))
    .join("");
}

/**
 * Generate a cryptographically random password guaranteeing at least one
 * character from each enabled character class.
 * @param {object} options
 * @param {number} [options.length=20]
 * @param {boolean} [options.uppercase=true]
 * @param {boolean} [options.lowercase=true]
 * @param {boolean} [options.numbers=true]
 * @param {boolean} [options.symbols=true]
 * @param {boolean} [options.excludeAmbiguous=false]
 * @returns {string}
 */
export function generatePassword({
  length = 20,
  uppercase = true,
  lowercase = true,
  numbers = true,
  symbols = true,
  excludeAmbiguous = false,
} = {}) {
  if (!Number.isInteger(length) || length < 8 || length > 128) {
    throw new Error("Password length must be an integer between 8 and 128.");
  }

  const activePools = [];
  if (lowercase) {
    activePools.push(filterCharset(CHARSETS.lowercase, excludeAmbiguous));
  }
  if (uppercase) {
    activePools.push(filterCharset(CHARSETS.uppercase, excludeAmbiguous));
  }
  if (numbers) {
    activePools.push(filterCharset(CHARSETS.numbers, excludeAmbiguous));
  }
  if (symbols) {
    activePools.push(filterCharset(CHARSETS.symbols, excludeAmbiguous));
  }

  const nonEmptyPools = activePools.filter((p) => p.length > 0);
  if (nonEmptyPools.length === 0) {
    throw new Error("Select at least one character set to generate a password.");
  }

  if (length < nonEmptyPools.length) {
    throw new Error(
      `Password length must be at least ${nonEmptyPools.length} to include all selected character sets.`
    );
  }

  const combinedPool = nonEmptyPools.join("");
  const passwordChars = [];

  // Guarantee at least one character from each selected character class
  for (const pool of nonEmptyPools) {
    const idx = uniformRandomIndex(pool.length);
    passwordChars.push(pool[idx]);
  }

  // Fill remaining characters uniformly from the combined character pool
  for (let i = passwordChars.length; i < length; i += 1) {
    const idx = uniformRandomIndex(combinedPool.length);
    passwordChars.push(combinedPool[idx]);
  }

  return secureShuffle(passwordChars).join("");
}

/**
 * Estimate password entropy and human-readable strength classification.
 * @param {string} password
 * @returns {{entropyBits: number, score: number, label: string, guidance: string}}
 */
export function estimatePasswordStrength(password) {
  if (typeof password !== "string" || password.length === 0) {
    return {
      entropyBits: 0,
      score: 0,
      label: "Empty",
      guidance: "Enter or generate a password.",
    };
  }

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 30;

  const uniqueChars = new Set(password).size;
  const repetitionPenalty = uniqueChars / password.length;
  const rawEntropy =
    poolSize > 0 ? password.length * Math.log2(poolSize) : 0;
  const entropyBits = Math.round(rawEntropy * (0.65 + 0.35 * repetitionPenalty));

  if (entropyBits < 45 || password.length < 8) {
    return {
      entropyBits,
      score: 1,
      label: "Weak",
      guidance: "Vulnerable to fast offline cracking. Increase length to 16+ characters.",
    };
  }
  if (entropyBits < 68 || password.length < 12) {
    return {
      entropyBits,
      score: 2,
      label: "Moderate",
      guidance: "Acceptable for low-risk accounts; prefer 16+ characters with mixed classes.",
    };
  }
  if (entropyBits < 95) {
    return {
      entropyBits,
      score: 3,
      label: "Strong",
      guidance: "Resistant to offline brute-force attacks.",
    };
  }
  return {
    entropyBits,
    score: 4,
    label: "Very Strong",
    guidance: "High-entropy cryptographic credential suitable for master and critical keys.",
  };
}
