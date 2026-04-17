(function () {
  'use strict';

  var golEnabled = window.innerWidth > 768;
  window._golEnabled = golEnabled;

  if (golEnabled) {
    var preload = document.createElement('link');
    preload.rel = 'preload';
    preload.href = '/static/wasm/gol.wasm';
    preload.as = 'fetch';
    preload.crossOrigin = '';
    document.head.appendChild(preload);

    var golScript = document.createElement('script');
    golScript.src = '/static/wasm/gol.js?v=43';
    golScript.async = false;
    document.body.appendChild(golScript);

    var heroScript = document.createElement('script');
    heroScript.src = '/static/js/gol-hero.js?v=53';
    heroScript.async = false;
    document.body.appendChild(heroScript);
  }

  setTimeout(function () { fetch('/beacon'); }, 60000);
}());
