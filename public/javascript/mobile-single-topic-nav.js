document.addEventListener("DOMContentLoaded", function () {
  const sidebar = document.getElementById("mobile-sidebar");
  const openBtn = document.querySelector(".more-topics");
  const closeBtn = document.getElementById("close-sidebar-btn");

  openBtn.addEventListener("click", () => {
    sidebar.style.left = "0";
  });

  closeBtn.addEventListener("click", () => {
    sidebar.style.left = "-100%";
  });

  document.addEventListener("click", (event) => {
    if (!sidebar.contains(event.target) && !openBtn.contains(event.target)) {
      sidebar.style.left = "-100%";
    }
  });
});