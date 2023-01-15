/// <reference lib="WebWorker" />

import { NerdCache } from "./js/NerdCache.js";

export type { };
declare const self: ServiceWorkerGlobalScope;

const CacheName = 'cache';
const CachedFiles = [
    "/offline.html",
    "/nerdlock.html",
    "/css/nerdlock.css",
    "/js/NerdClient.js",
    "/js/nerdlock.js",
    "/js/NerdUtils.js",
    "/js/CryptoHelper.js",
];

self.addEventListener('install', function (event) {
    event.waitUntil(
        caches.open(CacheName)
            .then(function (cache) {
                return cache.addAll(CachedFiles)
            })
    )
    self.skipWaiting()
})

self.addEventListener('fetch', function (event) {
    if (new URL(event.request.url).pathname.startsWith("/_nerdlock/"))
        return;

    if (event.request.mode === 'navigate') {
        event.respondWith(
            fetch(event.request)
                .catch(() => {
                    return caches.open(CacheName)
                        .then((cache) => {
                            return cache.match('/offline.html');
                        })
                })
        );
    }
    else {
        event.respondWith(
            fetch(event.request)
                .catch(() => {
                    return caches.open(CacheName)
                        .then((cache) => {
                            return cache.match(event.request)
                        })
                })
        );
    }
})

self.addEventListener('activate', function (event) {
    event.waitUntil(
        caches.keys()
            .then((keyList) => {
                return Promise.all(keyList.map((key) => {
                    if (key !== CacheName) {
                        console.log('[Nerdlock] Removing old cache', key)
                        return caches.delete(key)
                    }
                }))
            })
            .then(() => self.clients.claim())
    )
})

self.addEventListener("message", async function (event) {
    try {
        const message = JSON.parse(event.data);

        if (message.action === "saveDB") {
            const data = message.data as NerdCache;

            if (!(await indexedDB.databases()).find(db => db.name === "NerdCache"))
                return;

            const r = indexedDB.open("NerdCache", message.version);

            r.onsuccess = () => {
                try {
                    const db = r.result;

                    console.log(`[Nerdlock] Writing cache...`);
                    const transaction = db.transaction(["messages", "attachments"], "readwrite");

                    const messages = transaction.objectStore("messages");
                    for (const m of data.messages) {
                        const request = messages.put(m);
                        request.onsuccess = () => { ; }
                    }

                    const attachments = transaction.objectStore("attachments");
                    for (const a of data.attachments) {
                        const request = attachments.put(a);
                        request.onsuccess = () => { ; }
                    }
                } catch { ; }
            }
        }
    } catch (err) {
        console.warn(err);
    }
})