// Landing page JS — animations, misc
document.addEventListener('DOMContentLoaded', () => {
  // Animate feature cards
  const cards = document.querySelectorAll('.feature-card');
  const obs = new IntersectionObserver((entries) => {
    entries.forEach((e, i) => {
      if (e.isIntersecting) {
        setTimeout(() => { e.target.style.opacity = '1'; e.target.style.transform = 'translateY(0)'; }, i * 80);
        obs.unobserve(e.target);
      }
    });
  }, { threshold: 0.1 });
  cards.forEach(card => {
    card.style.opacity = '0'; card.style.transform = 'translateY(20px)';
    card.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    obs.observe(card);
  });
});
