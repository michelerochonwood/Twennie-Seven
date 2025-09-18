document.addEventListener("DOMContentLoaded", () => {
    const learning1Columns = document.querySelectorAll(".learning1-column");
  
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry, index) => {
          if (entry.isIntersecting) {
            setTimeout(() => {
              entry.target.classList.add("visible");
            }, index * 300); // Delay each column's animation by 300ms
          }
        });
      },
      { threshold: 0.5 } // Trigger animation when 50% of the column is visible
    );
  
    learning1Columns.forEach((column) => observer.observe(column));
  });
  