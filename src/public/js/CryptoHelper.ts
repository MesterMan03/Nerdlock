// NerdLock CryptoHelper by Mester
// This file contains utility functions for the WebCrypto API for easier use
// (seriously, who would want to use window.crypto.subtle.importKey("raw", new TextEncoder().encode("password"), "PBKDF2", false, ["deriveBits"]) only to turn a string into a key?)

const crypto = window.crypto.subtle;
if (!crypto) {
    alert("WebCrypto is not supported in your browser!");
}

/* Constants for CryptoHelper */
const textEnc = new TextEncoder();
const utfDec = new TextDecoder();
type HashType = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
type EncoderType = "utf-8" | "base64" | "hex";
/* -------------------------- */

/**
 * Utility function for generating a PBKDF2 key as a CryptoKey
 * @param secret The secret for the PBKDF2 key
 * @param salt The salt for the PBKDF2 key
 * @param iterations The number of iterations PBKDF2 should use
 * @param keyLen The desired length for the key (in bytes)
 * @param hash The hash algorithm PBKDF2 should use
 * @returns A CryptoKey that can be used for encryption/decryption
 */
async function generatePBKDF2(secret: string, salt: Uint8Array, iterations: number, keyLen: number, hash: HashType) {
    try {
        // import the secret as key
        const secretKey = await crypto.importKey("raw", textEnc.encode(secret), { name: "PBKDF2" }, false, ["deriveKey"]);

        return crypto.deriveKey({ name: "PBKDF2", salt, hash, iterations }, secretKey, { name: "AES-GCM", length: keyLen * 8 }, false, ["encrypt", "decrypt"]);
    } catch (err) {
        let error = err as Error;
        console.error("Error occured while trying to generate a PBKDF2 key: ", error.message, error.name, error.stack);
        return null;
    }
}

async function keyFromUint(password: Uint8Array) {
    return crypto.importKey("raw", password, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function UintToString(array: Uint8Array | ArrayBuffer, encoder: EncoderType = "utf-8") {
    const data = array instanceof Uint8Array ? array : new Uint8Array(array);
    switch (encoder) {
        case "utf-8": return utfDec.decode(data);
        case "base64": return window.btoa([...data].map(c => String.fromCharCode(c)).join(""));
        case "hex": return [...data].map(c => c.toString(16)).map(c => c.length === 1 ? "0" + c : c).join("");
    }
}

function StringToUint(input: string, encoder: EncoderType = "utf-8") {
    switch (encoder) {
        case "utf-8": return textEnc.encode(input);
        case "base64": return Uint8Array.from(window.atob(input), c => c.charCodeAt(0));
        case "hex": return Uint8Array.from((input.length % 2 === 0 ? input : "0" + input).match(/.{2}/g), c => parseInt(c, 16));
    }
}

export default {
    generatePBKDF2,
    keyFromUint,
    enc: {
        UintToString,
        StringToUint
    }
}