"use strict";
document.querySelectorAll("[data-logout]").forEach(function(button) {
 button.addEventListener("click", async function() {
  button.disabled=true;
  try { await fetch("/auth/logout",{method:"POST",credentials:"same-origin"}); }
  finally { window.location.assign("/"); }
 });
});
