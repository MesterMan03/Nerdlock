import CryptoHelper from "./CryptoHelper.js";
import { NerdMessage, NerdMessageContent, NerdPublicUser, NerdRawMessage, NerdRoom } from "./NerdClient.js";
import NerdCache from "./NerdCache.js";

/**
 * Function for decoding an incoming message from the server and adding it to the room
 * @param room The room the message belongs to
 * @param message The incoming message object
 * @param key The key for decrypting messages (optional)
 */
async function decodeRawMessage(room: NerdRoom, message: NerdRawMessage, author: NerdPublicUser, key?: CryptoKey, noEvent: boolean = false) {
    try {
        let found: NerdMessage;
        if (found = room.messages.find(m => m.messageId === message.messageId))
            return found;

        const ourKey = key || await CryptoHelper.keyFromUint(CryptoHelper.enc.StringToUint(room.secret, "base64"));

        // verify ciphertext
        let verified: boolean;
        if (!(verified = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-512" }, author.identityKey, CryptoHelper.enc.StringToUint(message.signature, "base64"), CryptoHelper.enc.StringToUint(message.cipherText))))
            console.warn(`Message ${message.messageId} from ${message.authorId} (${author.username}) could not be verified with the signature. Proceed with caution!`);

        const [iv, cipherText] = message.cipherText.split(".");
        const content = await crypto.subtle.decrypt({ name: "AES-GCM", iv: CryptoHelper.enc.StringToUint(iv, "base64") },
            ourKey, CryptoHelper.enc.StringToUint(cipherText, "base64"))
            .then(data => {
                try {
                    return JSON.parse(CryptoHelper.enc.UintToString(data)) as NerdMessageContent;
                } catch (err) {
                    return CryptoHelper.enc.UintToString(data) as any;
                }
            })
            .catch(err => { throw err; });

        const finalMessage: NerdMessage = {
            messageId: message.messageId,
            authorId: message.authorId,
            roomId: room.roomId,
            createdAt: message.createdAt,
            lastModifiedAt: message.lastModifiedAt,
            content,
            verified
        }

        room.messages.push(finalMessage);
        if (!NerdCache.messages.find(m => m.messageId === message.messageId))
            NerdCache.messages.push(message);

        if (!noEvent) window.dispatchEvent(new CustomEvent("nerdlock.newMessage", { detail: finalMessage }));

        return finalMessage;
    }
    catch (err) {
        console.error(err);
        console.log(`Failed to decode message ${message.messageId}`);
        return null;
    }
}

async function GetSecurityNumber(...publicKeys: string[]) {
    const publicKey = window.btoa(publicKeys.map(key => window.atob(key)).join(""));
    return CryptoHelper.enc.UintToString(await crypto.subtle.digest("SHA-512", CryptoHelper.enc.StringToUint(publicKey, "base64")), "hex")
        .match(/.{6}/g).join(" ");
}

function joinUint(...data: Uint8Array[] | ArrayBuffer[]) {
    return data.reduce((prev, curr) => {
        const newArray = new Uint8Array(prev.byteLength + curr.byteLength);
        newArray.set(prev);
        newArray.set(curr, prev.byteLength);
        return newArray;
    }) as Uint8Array;
}

async function waitForFocus() {
    return new Promise<void>((resolve, reject) => {
        if (window.document.hasFocus()) resolve();
        else
            window.addEventListener("focus", function a() {
                this.window.removeEventListener("focus", a);
                resolve();
            })
    })
}

export default {
    decodeRawMessage,
    GetSecurityNumber,
    joinUint,
    waitForFocus
}