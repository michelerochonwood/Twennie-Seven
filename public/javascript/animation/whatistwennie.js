document.addEventListener("DOMContentLoaded", () => {
    const whatistwennieItems = document.querySelectorAll(".whatistwennie-item");
  
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry, index) => {
          if (entry.isIntersecting) {
            setTimeout(() => {
              entry.target.classList.add("visible");
            }, index * 200); // Delay each icon's animation
          }
        });
      },
      { threshold: 0.5 }
    );
  
    whatistwennieItems.forEach((item) => observer.observe(item));
  });
  