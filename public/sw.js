/* GreenBox service worker: Web Push + basic PWA shell */
self.addEventListener('install', function () {
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(self.clients.claim());
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
