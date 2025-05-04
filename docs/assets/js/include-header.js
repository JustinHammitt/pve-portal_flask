// File: assets/js/include-header.js
document.addEventListener('DOMContentLoaded', () => {
    fetch('/assets/includes/header.html')
      .then(res => res.text())
      .then(html => {
        document.getElementById('site-header').innerHTML = html;
        // Optionally mark the active link:
        const path = location.pathname.split('/').pop();
        document.querySelectorAll('.nav-links a').forEach(a => {
          if (a.getAttribute('href') === path) a.classList.add('active');
        });
      })
      .catch(err => console.error('Header load failed:', err));
  });
  