(function () {
  'use strict';

  // Scan overlay scroll-to-hero
  var overlays = [document.getElementById('scanOverlay'), document.getElementById('scanOverlayRight')];
  overlays.forEach(function (el) {
    if (el) el.addEventListener('click', function () {
      document.querySelector('.hero').scrollIntoView({ behavior: 'smooth' });
    });
  });

  // Respect reduced motion preference
  var motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  if (motionQuery.matches) return;
  motionQuery.addEventListener('change', function (e) {
    if (e.matches) {
      var c = document.getElementById('gol-canvas');
      var intro = document.querySelector('.gol-intro');
      if (c) c.remove();
      if (intro) intro.style.display = 'none';
    }
  });

  var canvas = document.getElementById('gol-canvas');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  if (!ctx) return;

  var PIXEL = 4;
  var frameSkip = 3;
  var frameCount = 0;
  var rafId = 0;

  // --- Canvas sizing (fills .gol-intro container) ---
  function resize() {
    var container = canvas.parentElement;
    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight;
  }
  resize();

  var resizeTimer;
  window.addEventListener('resize', function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      resize();
      if (boundsUpdate) boundsUpdate();
    }, 150);
  });

  // --- Cell color: spawn=transparent, alive=solid green ---
  var colorAlive = 'rgb(34,197,94)';
  var colorSpawn = 'rgba(34,197,94,0.15)';

  function cellColor(age) {
    return age === 0 ? colorSpawn : colorAlive;
  }

  var visible = true;

  // --- WASM init ---
  var boundsUpdate = null;

  if (typeof GOLModule === 'undefined') {
    canvas.style.display = 'none';
    return;
  }

  GOLModule().then(function (mod) {
    var init = mod.cwrap('gol_init', null, ['number', 'number', 'number', 'number']);
    var spawn = mod.cwrap('gol_spawn', null, ['number', 'number', 'number', 'number']);
    var step = mod.cwrap('gol_step', 'number', []);
    var getCells = mod.cwrap('gol_get_cells', 'number', []);
    var setBounds = mod.cwrap('gol_set_bounds', null, ['number', 'number', 'number', 'number']);

    var shiftY = -Math.round(32 / PIXEL);
    init(0, shiftY, 4, -Math.PI / 4);

    function updateBounds() {
      var halfW = Math.floor(canvas.width / PIXEL / 2);
      var halfH = Math.floor(canvas.height / PIXEL / 2);
      setBounds(-halfW, -halfH, halfW, halfH);
    }
    updateBounds();
    boundsUpdate = updateBounds;

    // --- Render loop ---
    function render() {
      rafId = 0;
      if (!visible) return;
      frameCount++;
      if (frameCount % frameSkip !== 0) {
        rafId = requestAnimationFrame(render);
        return;
      }

      var count = step();
      if (count <= 0) { rafId = requestAnimationFrame(render); return; }
      var ptr = getCells();
      if (ptr <= 0 || ptr % 4 !== 0) { rafId = requestAnimationFrame(render); return; }

      // Re-read buffer each frame (may change on WASM memory growth)
      var buf = mod.wasmMemory.buffer;
      if (count > (buf.byteLength - ptr) / 12) {
        rafId = requestAnimationFrame(render);
        return;
      }

      var cells = new Int32Array(buf, ptr, count * 3);

      ctx.clearRect(0, 0, canvas.width, canvas.height);

      var cxOff = canvas.width / 2;
      var cyOff = canvas.height / 2;

      for (var i = 0; i < count * 3; i += 3) {
        ctx.fillStyle = cellColor(cells[i + 2]);
        ctx.fillRect(
          cxOff + cells[i] * PIXEL,
          cyOff + cells[i + 1] * PIXEL,
          PIXEL,
          PIXEL
        );
      }

      rafId = requestAnimationFrame(render);
    }

    rafId = requestAnimationFrame(render);

    // Pause when canvas not visible
    new IntersectionObserver(function (entries) {
      visible = entries[0].isIntersecting;
      if (visible && !rafId) rafId = requestAnimationFrame(render);
    }, { threshold: 0 }).observe(canvas);
  }).catch(function () {
    canvas.style.display = 'none';
  });
})();
