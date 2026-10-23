
const CACHE_NAME = "10bf-cache-v3";
const RUNTIME_CACHE = "10bf-runtime-v3";
const API_CACHE = "10bf-api-v3";

const APP_SHELL = [
    "/",
    "/index.html",
    "/style.css",
    "/app.js",
    "/manifest.json"
];

const APP_SHELL_ICON = "https://i.postimg.cc/vTLgTDnC/download.jpg";

const API_PREFIXES = [
    "/api/",
    "https://10blackfingers-api.vercel.app/api/"
];

const NEVER_CACHE_HOSTS = [
    "supabase.co",
    "api.github.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com"
];

function isApiRequest(url) {
    return API_PREFIXES.some(function (prefix) {
        return url.href.indexOf(prefix) !== -1;
    });
}

function isNeverCache(url) {
    return NEVER_CACHE_HOSTS.some(function (host) {
        return url.hostname.indexOf(host) !== -1;
    });
}

function isSameOrigin(url) {
    return url.origin === self.location.origin;
}

function isHtmlRequest(request, url) {
    if (request.mode === "navigate") return true;
    if (request.destination === "document") return true;
    if (url.pathname === "/" || url.pathname.endsWith(".html")) return true;
    return false;
}

function isStaticAsset(request, url) {
    var dest = request.destination;
    if (dest === "style" || dest === "script" || dest === "font") return true;
    if (dest === "image") return true;
    var ext = url.pathname.toLowerCase();
    return (
        ext.endsWith(".css") ||
        ext.endsWith(".js") ||
        ext.endsWith(".json") ||
        ext.endsWith(".png") ||
        ext.endsWith(".jpg") ||
        ext.endsWith(".jpeg") ||
        ext.endsWith(".svg") ||
        ext.endsWith(".webp") ||
        ext.endsWith(".gif") ||
        ext.endsWith(".ico") ||
        ext.endsWith(".woff") ||
        ext.endsWith(".woff2") ||
        ext.endsWith(".ttf") ||
        ext.endsWith(".otf")
    );
}

self.addEventListener("install", function (event) {
    event.waitUntil(
        (async function () {
            try {
                var cache = await caches.open(CACHE_NAME);
                await cache.addAll(APP_SHELL).catch(function () {});
                try {
                    await cache.add(APP_SHELL_ICON).catch(function () {});
                } catch (e) {}
            } catch (e) {}
            await self.skipWaiting();
        })()
    );
});

self.addEventListener("activate", function (event) {
    event.waitUntil(
        (async function () {
            try {
                var keys = await caches.keys();
                await Promise.all(
                    keys.map(function (key) {
                        if (key !== CACHE_NAME && key !== RUNTIME_CACHE && key !== API_CACHE) {
                            return caches.delete(key);
                        }
                        return Promise.resolve();
                    })
                );
            } catch (e) {}
            if (self.registration.navigationPreload) {
                try {
                    await self.registration.navigationPreload.disable();
                } catch (e) {}
            }
            await self.clients.claim();
        })()
    );
});

self.addEventListener("message", function (event) {
    if (event.data && event.data.type === "SKIP_WAITING") {
        self.skipWaiting();
    }
    if (event.data && event.data.type === "CLEAR_CACHE") {
        event.waitUntil(
            (async function () {
                try {
                    var keys = await caches.keys();
                    await Promise.all(
                        keys.map(function (k) {
                            return caches.delete(k);
                        })
                    );
                } catch (e) {}
            })()
        );
    }
});

async function networkFirstHtml(request) {
    var cache = await caches.open(CACHE_NAME);
    try {
        var response = await fetch(request);
        if (response && response.status === 200) {
            try {
                await cache.put(request, response.clone());
            } catch (e) {}
        }
        return response;
    } catch (e) {
        var cached = await cache.match(request);
        if (cached) return cached;
        var fallback = await cache.match("/index.html");
        if (fallback) return fallback;
        var root = await cache.match("/");
        if (root) return root;
        return new Response(
            "<!DOCTYPE html><html lang=\"ar\" dir=\"rtl\"><head><meta charset=\"UTF-8\"><title>Offline</title></head><body style=\"font-family:sans-serif;text-align:center;padding:60px;background:#0a0a0a;color:#e5e7eb;\"><h1 style=\"color:#00ff41;\">أنت غير متصل بالإنترنت</h1><p>من فضلك تحقق من اتصالك ثم حاول مرة أخرى.</p></body></html>",
            {
                status: 200,
                headers: { "Content-Type": "text/html; charset=utf-8" }
            }
        );
    }
}

async function cacheFirstAsset(request) {
    var cache = await caches.open(CACHE_NAME);
    var cached = await cache.match(request);
    if (cached) {
        fetch(request)
            .then(function (response) {
                if (response && response.status === 200) {
                    cache.put(request, response.clone()).catch(function () {});
                }
            })
            .catch(function () {});
        return cached;
    }
    try {
        var response = await fetch(request);
        if (response && response.status === 200) {
            try {
                await cache.put(request, response.clone());
            } catch (e) {}
        }
        return response;
    } catch (e) {
        var fallback = await cache.match(request);
        if (fallback) return fallback;
        return new Response("", {
            status: 504,
            statusText: "Offline"
        });
    }
}

async function staleWhileRevalidate(request) {
    var cache = await caches.open(RUNTIME_CACHE);
    var cached = await cache.match(request);
    var fetchPromise = fetch(request)
        .then(function (response) {
            if (response && response.status === 200) {
                cache.put(request, response.clone()).catch(function () {});
            }
            return response;
        })
        .catch(function () {
            return cached;
        });
    return cached || fetchPromise;
}

self.addEventListener("fetch", function (event) {
    var request = event.request;

    if (request.method !== "GET") {
        return;
    }

    var url;
    try {
        url = new URL(request.url);
    } catch (e) {
        return;
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
        return;
    }

    if (isApiRequest(url)) {
        return;
    }

    if (isNeverCache(url)) {
        return;
    }

    if (request.headers && request.headers.get("range")) {
        return;
    }

    if (isHtmlRequest(request, url)) {
        event.respondWith(networkFirstHtml(request));
        return;
    }

    if (isSameOrigin(url) && isStaticAsset(request, url)) {
        event.respondWith(cacheFirstAsset(request));
        return;
    }

    if (url.origin === "https://i.postimg.cc") {
        event.respondWith(cacheFirstAsset(request));
        return;
    }

    if (isSameOrigin(url)) {
        event.respondWith(staleWhileRevalidate(request));
        return;
    }
});

self.addEventListener("notificationclick", function (event) {
    event.notification.close();
    event.waitUntil(
        (async function () {
            var allClients = await self.clients.matchAll({
                type: "window",
                includeUncontrolled: true
            });
            for (var i = 0; i < allClients.length; i++) {
                var client = allClients[i];
                if (client.url && "focus" in client) {
                    return client.focus();
                }
            }
            if (self.clients.openWindow) {
                return self.clients.openWindow("/");
            }
        })()
    );
});

self.addEventListener("sync", function (event) {
    if (event.tag === "sync-scans") {
        event.waitUntil(
            (async function () {
                try {
                    var clients = await self.clients.matchAll({ includeUncontrolled: true });
                    clients.forEach(function (client) {
                        client.postMessage({ type: "SYNC_SCANS" });
                    });
                } catch (e) {}
            })()
        );
    }
});
