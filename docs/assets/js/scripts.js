//<!-- File: assets/js/scripts.js -->
document.addEventListener('DOMContentLoaded', function() {
  const carousel = document.querySelector('.carousel');
  if (carousel) {
    const images = carousel.querySelectorAll('img');
    let current = 0;
    const prev = carousel.querySelector('.carousel-prev');
    const next = carousel.querySelector('.carousel-next');
    function update() {
      images.forEach((img, i) => img.style.display = i === current ? 'block' : 'none');
    }
    prev.addEventListener('click', () => { current = (current - 1 + images.length) % images.length; update(); });
    next.addEventListener('click', () => { current = (current + 1) % images.length; update(); });
    update();
  }
});
