/* Service worker MAD.U - rede primeiro, cache como reserva (offline).
   Para forçar atualização em todos os aparelhos, aumente o número da VERSION. */
const VERSION = 'v1';
const CACHE = 'pedidos-vtex-madu-' + VERSION;
const SHELL = ['./', 'manifest.json', 'icons/icon-192.png', 'icons/icon-512.png'];
const SKIP_EXT = /\.(glb|gltf|usdz|mp4|webm|mov|hdr|zip)(\?.*)?$/i;

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) =>
      Promise.allSettled(SHELL.map((url) => cache.add(url)))
    ).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('pedidos-vtex-madu-') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;      // APIs e CDNs externos: direto da rede
  if (req.headers.has('range') || SKIP_EXT.test(url.pathname)) return; // arquivos grandes: sem cache

  event.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.status === 200 && res.type === 'basic') {
          const copy = res.clone();
          caches.open(CACHE).then((cache) => cache.put(req, copy));
        }
        return res;
      })
      .catch(() =>
        caches.match(req).then((hit) => hit || (req.mode === 'navigate' ? caches.match('./') : undefined))
      )
  );
});
