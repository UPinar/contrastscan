document.addEventListener('DOMContentLoaded', function() {
  var btn = document.querySelector('.hamburger');
  if (btn) {
    btn.addEventListener('click', function() {
      var o = this.getAttribute('aria-expanded') === 'true';
      this.setAttribute('aria-expanded', String(!o));
      document.querySelector('.nav-links').classList.toggle('open');
    });
  }
});
