document.addEventListener('DOMContentLoaded', function() {
  var scanForm = document.getElementById('scanForm');
  var scanBtn = document.getElementById('scanBtn');
  var bulkFile = document.getElementById('bulkFile');
  var bulkBtn = document.querySelector('.btn-bulk');
  var testUsLink = document.querySelector('.test-us');

  if (scanForm) {
    scanForm.addEventListener('submit', function() {
      scanBtn.disabled = true;
      scanBtn.textContent = 'Scanning...';
    });
  }

  window.addEventListener('pageshow', function() {
    if (scanBtn) { scanBtn.disabled = false; scanBtn.textContent = 'Scan Now'; }
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

  if (testUsLink) {
    testUsLink.addEventListener('click', function(e) {
      e.preventDefault();
      document.querySelector('input[name=domain]').value = 'contrastcyber.com';
      scanForm.submit();
    });
  }
});
