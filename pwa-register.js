// Registra o service worker (necessário para instalar o app).
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function () {
    navigator.serviceWorker.register('sw.js').catch(function (e) {
      console.warn('Service worker não registrado:', e);
    });
  });
}
