/* GreenBox service worker: PWA shell, offline fallback and Web Push */
const CACHE_NAME = 'greenbox-v2';
const PRECACHE = [
  '/offline.html',
  '/icon-192.png',
  '/icon-512.png',
  '/manifest.webmanifest',
  '/style.css',
  '/script.js',
  '/presence.js',
  '/icons.svg'
];

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(function (cache) { return cache.addAll(PRECACHE); })
      .catch(function () {})
      .then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (key) {
        if (key !== CACHE_NAME) return caches.delete(key);
        return null;
      }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('message', function (event) {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', function (event) {
  const request = event.request;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(function () {
        return caches.match('/offline.html');
      })
    );
    return;
  }

  const cacheable = PRECACHE.indexOf(url.pathname) >= 0;
  if (!cacheable) return;

  event.respondWith(
    fetch(request)
      .then(function (response) {
        if (response && response.ok) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then(function (cache) { cache.put(request, copy); }).catch(function () {});
        }
        return response;
      })
      .catch(function () {
        return caches.match(request).then(function (cached) {
          return cached || new Response('', { status: 503, statusText: 'Offline' });
        });
      })
  );
});

self.addEventListener('push', function (event) {
  var data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { title: 'GreenBox', body: event.data ? event.data.text() : '' };
  }

  var title = data.title || 'GreenBox 通知';
  var options = {
    body: String(data.body || '').slice(0, 240),
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    tag: data.id || 'greenbox',
    renotify: false,
    data: {
      url: typeof data.url === 'string' && data.url.charAt(0) === '/' ? data.url : '/notifications.html'
    }
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  var url = (event.notification.data && event.notification.data.url) || '/notifications.html';

  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (windows) {
      for (var i = 0; i < windows.length; i++) {
        var client = windows[i];
        if ('focus' in client) {
          if (client.navigate) client.navigate(url).catch(function () {});
          return client.focus();
        }
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
      return null;
    })
  );
});
