// Select each specific partial container class individually
const partials = document.querySelectorAll('.latestpartial1-container, .latestpartial2-container, .latestpartial3-container');

// Options for the IntersectionObserver
const observerOptions = {
  threshold: 0.5, // Trigger animation when 10% of the partial is visible
};

// Create the IntersectionObserver
const observer = new IntersectionObserver((entries, observer) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.classList.add('animate-move-in');
      observer.unobserve(entry.target); // Stop observing once the animation is triggered
    }
  });
}, observerOptions);

// Observe each partial
partials.forEach(partial => {
  observer.observe(partial);
});