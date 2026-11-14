(function () {
  'use strict';
  var token = '';
  try { token = localStorage.getItem('greenbox_token') || ''; } catch (e) {}
  if (!token || window.__gbPresenceSocket) return;

  function connect() {
    if (window.__gbPresenceSocket) return;
    if (!window.io) {
      if (document.querySelector('script[data-gb-presence]')) return;
      var script = document.createElement('script');
      script.src = '/socket.io/socket.io.js';
      script.async = true;
      script.setAttribute('data-gb-presence', '1');
      script.onload = connect;
      script.onerror = function () {};
      document.head.appendChild(script);
      return;
    }
    try {
      var socket = io({ transports: ['websocket', 'polling'] });
      window.__gbPresenceSocket = socket;
      socket.on('connect', function () {
        var current = '';
        try { current = localStorage.getItem('greenbox_token') || ''; } catch (e) {}
        if (current) socket.emit('dm:auth', { token: current });
      });
    } catch (e) {}
  }

  connect();
})();
