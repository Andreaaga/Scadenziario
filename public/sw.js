// Service worker: riceve le notifiche push e le mostra. Non salva nulla in cache (l'app richiede la connessione).
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) { d = { body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(d.title || 'Scadenzario', {
    body: d.body || '', tag: d.tag || 'scadenzario', icon: '/icons/icon-192.png', data: { url: d.url || '/' }
  }));
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const list = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of list) { if ('focus' in c) { await c.focus(); return; } }
    await self.clients.openWindow((e.notification.data && e.notification.data.url) || '/');
  })());
});
