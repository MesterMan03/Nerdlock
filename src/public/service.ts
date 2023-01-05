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
    "/img/user-picture.svg",
    "/img/upload-button.svg",
    "/img/send.png"
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

self.addEventListener("message", function (event) {
    try {
        const message = JSON.parse(event.data);

        if (message.action === "saveDB") {
            const data = message.data as NerdCache;

            const r = indexedDB.open("NerdCache", message.version);

            r.onsuccess = () => {
                try {

                    const db = r.result;

                    console.log(`[Nerdlock] Writing cache...`);
                    const transaction = db.transaction(["messages"], "readwrite");

                    const messages = transaction.objectStore("messages");
                    for (const m of data.messages) {
                        const request = messages.put(m);
                        request.onsuccess = () => { ; }
                    }
                } catch { ; }
            }
        }
    } catch (err) {
        console.warn(err);
    }
})