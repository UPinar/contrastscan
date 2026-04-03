document.addEventListener('DOMContentLoaded', function() {
  var scanForm = document.getElementById('scanForm');
  var scanBtn = document.getElementById('scanBtn');
  var bulkFile = document.getElementById('bulkFile');
  var bulkBtn = document.querySelector('.btn-bulk');

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

  if (bulkBtn) {
    bulkBtn.addEventListener('click', function() {
      bulkFile.click();
    });
  }

  if (bulkFile) {
    bulkFile.addEventListener('change', function(e) {
      var file = e.target.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function(ev) {
        sessionStorage.setItem('bulkDomains', ev.target.result);
        window.location.href = '/bulk';
      };
      reader.readAsText(file);
    });
  }
});
