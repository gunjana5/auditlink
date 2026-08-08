// shared expiry countdown for result + download pages
(function () {
  var el = document.getElementById("expiry-countdown");
  if (!el) return;
  // iso string from the server - Date.parse handles the +00:00
  var expiresAt = Date.parse(el.getAttribute("data-expires-at"));
  if (isNaN(expiresAt)) return;

  function pad(n) { return String(n); }

  function tick() {
    var ms = expiresAt - Date.now();
    if (ms <= 0) {
      el.textContent = "";
      return;
    }
    var totalSec = Math.floor(ms / 1000);
    var h = Math.floor(totalSec / 3600);
    var m = Math.floor((totalSec % 3600) / 60);
    var s = totalSec % 60;
    // once past an hour just refresh every minute - no need for second precision
    if (h >= 1) {
      el.textContent = " · expires in " + pad(h) + "h " + pad(m) + "m";
      setTimeout(tick, 60 * 1000);
    } else {
      el.textContent = " · expires in " + pad(h) + "h " + pad(m) + "m " + pad(s) + "s";
      setTimeout(tick, 1000);
    }
  }
  tick();
})();
