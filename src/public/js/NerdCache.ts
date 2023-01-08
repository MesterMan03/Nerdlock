import { NerdPublicUser, NerdRawMessage } from "./NerdClient.js"

export interface NerdCache {
    messages: NerdRawMessage[];
    users: NerdPublicUser[];
}

let db: IDBDatabase;
export const cache: NerdCache = { messages: [], users: [] };

const r = window.indexedDB.open("NerdCache", 1);

r.onsuccess = async () => {
    db = r.result;

    await loadCache();
};

r.onupgradeneeded = async (ev) => {
    //@ts-expect-error
    db = ev.target.result;

    db.createObjectStore("messages", { keyPath: "messageId" });
    db.createObjectStore("users", { keyPath: "userId" });
}

window.addEventListener("beforeunload", async () => {
    await storeCache();
});

async function loadCache() {
    try {
        console.log(`[Nerdlock] Loading cache...`);
        const transaction = db.transaction(["messages"], "readonly");

        const messages = transaction.objectStore("messages");
        messages.openCursor().onsuccess = (ev) => {
            //@ts-expect-error
            const cursor = ev.target.result as IDBCursorWithValue;
            if (!cursor) return;

            cache.messages.push(cursor.value);

            cursor.continue();
        }
        cache.messages = cache.messages.sort((a, b) => a.createdAt - b.createdAt);
    } catch { ; }
}

async function storeCache() {
    navigator.serviceWorker.controller.postMessage(JSON.stringify({
        action: "saveDB",
        version: db.version,
        data: cache
    }));
}

export default cache;
