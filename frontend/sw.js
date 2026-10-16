const CACHE_NAME = "10bf-cyber-cache-v2";
const APP_SHELL = [
    "/",
    "/index.html",
    "/style.css",
    "/app.js",
    "/manifest.json"
];

self.addEventListener("install", (e) => {
    e.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(APP_SHELL))
            .catch(() => {})
    );
    self.skipWaiting();
});

self.addEventListener("activate", (e) => {
    e.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(
                keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
            )
        )
    );
    self.clients.claim();
});

self.addEventListener("fetch", (e) => {
    const url = new URL(e.request.url);

    // استثناء تام لطلبات الـ API أو التقارير لضمان جلب البيانات الحية دائماً
    if (e.request.method !== "GET" || url.pathname.includes("/api/")) {
        return;
    }

    e.respondWith(
        caches.match(e.request).then((cached) => {
            if (cached) {
                // تحديث الذاكرة المؤقتة في الخلفية عند توافر اتصال
                fetch(e.request).then((response) => {
                    if (response && response.status === 200) {
                        caches.open(CACHE_NAME).then((cache) => cache.put(e.request, response));
                    }
                }).catch(() => {});
                return cached;
            }

            return fetch(e.request)
                .then((response) => {
                    if (response && response.status === 200) {
                        const clone = response.clone();
                        caches.open(CACHE_NAME).then((cache) => cache.put(e.request, clone));
                    }
                    return response;
                })
                .catch(() => caches.match("/index.html"));
        })
    );
});