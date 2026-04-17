document.addEventListener('DOMContentLoaded', function() {
  var btn = document.querySelector('.hamburger');
  if (btn) {
    btn.addEventListener('click', function() {
      var o = this.getAttribute('aria-expanded') === 'true';
      this.setAttribute('aria-expanded', String(!o));
      document.querySelector('.nav-links').classList.toggle('open');
    });
  }

  var CONTACT_EMAIL = 'contact@contrastcyber.com';
  document.querySelectorAll('.contact-copy').forEach(function(el) {
    el.addEventListener('click', function(e) {
      e.preventDefault();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(CONTACT_EMAIL);
      }
      var orig = el.textContent;
      el.textContent = 'Copied!';
      setTimeout(function() { el.textContent = orig; }, 1500);
    });
  });
});
