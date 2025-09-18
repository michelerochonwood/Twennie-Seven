document.addEventListener("DOMContentLoaded", function () {
  const animatedBg = document.querySelector(".animated-background");
  const titles = document.querySelectorAll(".twennie-title-text");
  let index = 0;

  function cycleTitles() {
      titles.forEach((title, i) => {
          title.classList.remove("active");
          if (i === index) {
              title.classList.add("active");
          }
      });

      index = (index + 1) % titles.length;
  }

  setInterval(cycleTitles, 4000); // Change title every 4 seconds

  function adjustAnimationSpeed() {
      const viewportWidth = window.innerWidth;
      let animationSpeed = viewportWidth > 1200 ? 40 : viewportWidth > 768 ? 30 : 20;
      animatedBg.style.animationDuration = `${animationSpeed}s`;
  }

  adjustAnimationSpeed();
  window.addEventListener("resize", adjustAnimationSpeed);
});

