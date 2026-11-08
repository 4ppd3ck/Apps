'use strict';
/* app.js — wGrid shell: theme toggle + machine line. The feed UI lives in
   js/feed.js; this file only carries the page furniture the w-family
   servers share. */

const $ = (s) => document.querySelector(s);

/* ---------- theme ---------- */

$('#themeBtn').addEventListener('click', () => {
  const cur = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = cur;
  try { localStorage.setItem('wgrid.theme', cur); } catch (e) {}
  $('#themeBtn').textContent = cur === 'light' ? '☀️' : '🌙';
});
try {
  $('#themeBtn').textContent =
    document.documentElement.dataset.theme === 'light' ? '☀️' : '🌙';
} catch (e) {}

/* ---------- machine line ---------- */

(async () => {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    const nets = d.networks ?? 0;
    $('#machine').textContent = `${nets} networks · updated ${d.updated_at ? new Date(d.updated_at * 1000).toLocaleTimeString() : 'never'}`;
  } catch (e) { /* cosmetic */ }
})();
