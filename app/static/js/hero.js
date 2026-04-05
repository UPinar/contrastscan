(function(){
  var input = document.getElementById("domainInput");
  if (!input) return;
  var form = document.getElementById("scanForm");

  // Referrer pre-fill: if visitor came from another site, pre-fill that domain
  try {
    var ref = document.referrer;
    if (ref) {
      var refHost = new URL(ref).hostname.toLowerCase();
      if (refHost && refHost.indexOf("contrastcyber") === -1 &&
          refHost.indexOf("google") === -1 && refHost.indexOf("bing") === -1 &&
          refHost.indexOf("duckduckgo") === -1 && refHost.indexOf("yahoo") === -1) {
        input.value = refHost;
      }
    }
  } catch(e) {}

  // Animated placeholder cycling
  var domains = ["github.com","cloudflare.com","your-site.com","google.com"];
  var i = 0;
  setInterval(function(){
    if (input.value || document.activeElement === input) return;
    input.placeholder = domains[i];
    i = (i + 1) % domains.length;
  }, 2000);

  // Preview card click -> scan contrastcyber.com
  var card = document.querySelector(".preview-card");
  if (card) card.addEventListener("click", function(){
    input.value = "contrastcyber.com";
    form.submit();
  });

  // "See a sample report" button -> scan contrastcyber.com
  var sample = document.querySelector(".try-sample");
  if (sample) sample.addEventListener("click", function(){
    input.value = "contrastcyber.com";
    form.submit();
  });
})();
