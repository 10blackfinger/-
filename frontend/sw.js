const CACHE_NAME = "10bf-cache-v1";
const APP_SHELL = ["/", "/index.html", "/style.css", "/app.js", "/manifest.json"];

self.addEventListener("install", (e) => {
    e.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)).catch(() => {})
    );
    self.skipWaiting();
});

self.addEventListener("activate", (e) => {
    e.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
        )
    );
    self.clients.claim();
});

self.addEventListener("fetch", (e) => {
    // منخزنش مؤقتًا أي حاجة غير GET، ومنلمسش طلبات الـ API (scan/report)
    // عشان نفاداي أي نتايج قديمة/مخزنة بالغلط
    if (e.request.method !== "GET" || e.request.url.includes("/api/")) {
        return;
    }

    e.respondWith(
        caches.match(e.request).then((cached) => {
            if (cached) return cached;
            return fetch(e.request)
                .then((response) => {
                    if (response && response.status === 200) {
                        const clone = response.clone();
                        caches.open(CACHE_NAME).then((cache) => cache.put(e.request, clone));
                    }
                    return response;
                })
                .catch(() => cached);
        })
    );
});