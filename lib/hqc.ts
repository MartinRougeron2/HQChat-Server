import {load, IKoffiLib, array, struct, decode, encode} from 'koffi';

// ==========================================
// 1. CONFIGURATION & CONSTANTS
// ==========================================
const PARAM_N = 57637;
const VEC_N_SIZE_64 = Math.ceil(PARAM_N / 64); // 901

export const HQC_CONSTANTS = {
  PARAM_K: 24,                    
  SEED_BYTES: 32,
  PUBLIC_KEY_BYTES: 7237,
  SECRET_KEY_BYTES: 7333,
  VEC_N_SIZE_64: VEC_N_SIZE_64,
  // Ciphertext size = 2 arrays * 901 uint64s * 8 bytes
  CIPHERTEXT_SIZE_BYTES: 2 * VEC_N_SIZE_64 * 8 
};

// ==========================================
// 2. LOAD LIBRARIES
// ==========================================

// A. Load your HQC Library
let libHQC: IKoffiLib;
try {
  libHQC = load("./lib/libhqc_x86.so");
} catch (e) {
  console.error("Could not load hqc lib.", e);
  throw e;
}

// B. Load Standard C Library (for 'free')
// We need this to free the memory allocated by malloc in your C code.
let libC: IKoffiLib;

try {
  libC = load('libc.so.6');
} catch (e) {
  console.warn("Could not load libc for free(). Memory leaks may occur.", e);
  // Fallback: If your libhqc.so exports 'free' dynamically, we try to use that.
  libC = libHQC; 
}

// ==========================================
// 3. DEFINE TYPES & FUNCTIONS
// ==========================================

// Define the 'free' function signature
const c_free = libC.func("free", "void", ["void*"]);

// Define HQC Structs
const CiphertextPkeStruct = struct("ciphertext_pke_t", {
  u: array("uint64", HQC_CONSTANTS.VEC_N_SIZE_64),
  v: array("uint64", HQC_CONSTANTS.VEC_N_SIZE_64),
});

const HqcKeypairStruct = struct("hqc_keypair_t", {
  pk: "uint8*", 
  sk: "uint8*", 
});

// 2. Define Function (Returns a Pointer to the struct)
const hqc_keygen_wrap = libHQC.func("hqc_keygen_wrap", "hqc_keypair_t*", ["uint8*"]);
// ciphertext_pke_t* hqc_encrypt_wrap(const uint8_t pk[], const uint8_t msg[], const uint8_t theta[]);
const hqc_encrypt_wrap = libHQC.func("hqc_encrypt_wrap", "ciphertext_pke_t*", ["uint8*", "uint8*", "uint8*"]);
const hqc_decrypt_wrap = libHQC.func("hqc_decrypt_wrap", "uint8*", ["uint8*", "ciphertext_pke_t*"]);
// ==========================================
// 4. WRAPPER CLASS
// ==========================================

export class HqcWrapper {
  
  static generateKeypair(seed: Buffer | number[]) {
    // FIX 1: Input must be a TypedArray (Buffer or Uint8Array)
    // Koffi cannot pass a plain JS Array [1, 2...] to a C pointer.
    const seedTyped = new Uint8Array(seed);

    if (seedTyped.length !== HQC_CONSTANTS.SEED_BYTES) {
      throw new Error(`Seed must be ${HQC_CONSTANTS.SEED_BYTES} bytes`);
    }

    // Call C Function
    // returns: a pointer (External object)
    const keypairPtr = hqc_keygen_wrap(seedTyped);

    if (!keypairPtr) throw new Error("HQC Keygen failed (returned null pointer)");

    try {
      // FIX 2: Decode the Pointer to get the Struct
      // We read 'HqcKeypairStruct' from the memory address 'keypairPtr'
      const keypair = decode(keypairPtr, "hqc_keypair_t");

      // Now 'keypair' is a JS Object: { pk: [External], sk: [External] }
      // FIX 3: Decode the inner pointers (pk/sk) to get the actual bytes
      const pkBytes = decode(keypair.pk, "uint8", HQC_CONSTANTS.PUBLIC_KEY_BYTES);
      const skBytes = decode(keypair.sk, "uint8", HQC_CONSTANTS.SECRET_KEY_BYTES);

      return {
        pk: Buffer.from(pkBytes),
        sk: Buffer.from(skBytes),
      };

    } finally {
      // FIX 4: Free the main struct pointer
      // (Assuming the C function malloc'd this struct and expects you to free it)
      c_free(keypairPtr);
    }
  }

  static encrypt(pk: Buffer, message: Buffer, theta: Buffer) {
    if (pk.length !== HQC_CONSTANTS.PUBLIC_KEY_BYTES) throw new Error("Invalid PK length");
    if (message.length !== HQC_CONSTANTS.PARAM_K) throw new Error("Invalid Message length");
    if (theta.length !== HQC_CONSTANTS.SEED_BYTES) throw new Error("Invalid Theta length");

    // 1. Call C Function
    const ctPtr = hqc_encrypt_wrap(pk, message, theta);

    if (!ctPtr) throw new Error("HQC Encrypt failed");

    try {
      // 2. Extract Data
      // Decode the entire struct memory into a raw byte array
      const rawBytes = decode(ctPtr, "uint8", HQC_CONSTANTS.CIPHERTEXT_SIZE_BYTES);
      
      return Buffer.from(rawBytes);

    } finally {
      // 3. CLEANUP: Free the ciphertext struct
      c_free(ctPtr);
    }
  }

 static decrypt(sk: Buffer, ciphertext: Buffer): Buffer {
    if (sk.length !== HQC_CONSTANTS.SECRET_KEY_BYTES) throw new Error("Invalid SK length");
    if (ciphertext.length !== HQC_CONSTANTS.CIPHERTEXT_SIZE_BYTES) throw new Error("Invalid Ciphertext length");

    // 1. Decode Ciphertext Buffer back into a Pointer
    // Koffi can automatically cast a Buffer to a pointer for "uint8*", 
    // but for a struct pointer ("ciphertext_pke_t*"), we must be careful.
    // Since 'ciphertext' is just a byte array matching the struct layout, 
    // we can pass the buffer directly. Koffi treats Buffer as a memory address.
    
    // 2. Call C Function
    // The C function allocates memory for the result and returns a pointer.
    const msgPtr = hqc_decrypt_wrap(sk, ciphertext);

    if (!msgPtr) throw new Error("HQC Decrypt failed (returned null pointer)");

    try {
      // 3. Extract Data
      // We know the output message length is exactly PARAM_K
      const msgBytes = decode(msgPtr, "uint8", HQC_CONSTANTS.PARAM_K);

      // Return a Node.js Buffer (deep copy)
      return Buffer.from(msgBytes);

    } finally {
      // 4. CLEANUP: Free the message memory allocated by C
      c_free(msgPtr);
    }
  }
}