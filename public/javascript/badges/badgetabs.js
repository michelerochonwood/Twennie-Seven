document.addEventListener("DOMContentLoaded", function () {
  // Get all tab wrappers
  const wrappers = document.querySelectorAll(".tabs-column .tab-wrapper");
  // Also get the inner tabs for click handling
  const tabs = document.querySelectorAll(".tabs-column .tab");
  // Get all individual badge tab content containers
  const contents = document.querySelectorAll(".badges-tab-content");
  // Get the main badge content container
  const badgeContentContainer = document.querySelector(".badge-content");

  // Set up click event listener for each tab (use the inner tab)
  tabs.forEach(tab => {
    tab.addEventListener("click", function () {
      const target = this.getAttribute("data-target");

      // Remove active class from all tabs and contents
      tabs.forEach(t => t.classList.remove("active"));
      contents.forEach(c => c.classList.remove("active"));

      // Add active class to clicked tab and its corresponding content
      this.classList.add("active");
      const content = document.getElementById(target);
      if (content) {
        content.classList.add("active");
      }
      // Adjust badge content container's top margin using the parent wrapper's offset
      const offset = this.parentNode.offsetTop;
      badgeContentContainer.style.marginTop = offset + "px";
    });
  });

  // Activate the first tab and its content by default, if available
  if (tabs.length > 0 && contents.length > 0) {
    tabs[0].classList.add("active");
    const firstTarget = tabs[0].getAttribute("data-target");
    const firstContent = document.getElementById(firstTarget);
    if (firstContent) {
      firstContent.classList.add("active");
    }
    badgeContentContainer.style.marginTop = tabs[0].parentNode.offsetTop + "px";
  }
});






