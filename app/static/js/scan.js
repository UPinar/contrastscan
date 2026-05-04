document.addEventListener('DOMContentLoaded', function() {
  var scanForm = document.getElementById('scanForm');
  var scanBtn = document.getElementById('scanBtn');

  if (scanForm) {
    scanForm.addEventListener('submit', function() {
      scanBtn.disabled = true;
      scanBtn.textContent = 'Scanning...';
    });
  }

  window.addEventListener('pageshow', function() {
    if (scanBtn) { scanBtn.disabled = false; scanBtn.textContent = 'Scan Now'; }
  });

  document.querySelectorAll('.try-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var domain = btn.getAttribute('data-domain');
      document.querySelector('input[name=domain]').value = domain;
      scanForm.requestSubmit();
    });
  });
});
