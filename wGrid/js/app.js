'use strict';
/* app.js — wGrid shell: theme toggle. The feed UI lives in js/feed.js; the
   machine line is filled from the same /api/status payload feed.js already
   fetches, so this file only carries the page furniture. */

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
