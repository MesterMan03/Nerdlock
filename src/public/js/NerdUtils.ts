import CryptoHelper from "./CryptoHelper.js";

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
    GetSecurityNumber,
    joinUint,
    waitForFocus
}