document.addEventListener("DOMContentLoaded", function () {
  const allTabs = document.querySelectorAll(".dashboard-tab");
  const allContents = document.querySelectorAll(".dashboard-tab-content");

  allTabs.forEach(tab => {
    tab.addEventListener("click", function () {
      const targetId = this.getAttribute("data-tab");

      // Deactivate all tabs
      allTabs.forEach(t => t.classList.remove("active"));
      allContents.forEach(c => {
        c.classList.remove("active");
        c.style.display = "none";
      });

      // Activate clicked tab and show corresponding content
      this.classList.add("active");
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add("active");
        targetContent.style.display = "block";
      }
    });
  });

  // On page load: ensure only the active tab content is visible
  allContents.forEach(c => {
    if (!c.classList.contains("active")) {
      c.style.display = "none";
    } else {
      c.style.display = "block";
    }
  });
});



