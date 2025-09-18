document.addEventListener("DOMContentLoaded", function () {
    const animatedBg = document.querySelector(".animated-background");

    function adjustAnimationSpeed() {
        const viewportWidth = window.innerWidth;
        let animationSpeed;

        if (viewportWidth > 1200) {
            animationSpeed = 40; // Slowest speed for large screens
        } else if (viewportWidth > 768) {
            animationSpeed = 30; // Medium speed for tablets
        } else {
            animationSpeed = 20; // Faster movement for smaller screens
        }

        animatedBg.style.animationDuration = `${animationSpeed}s`;
    }

    adjustAnimationSpeed();
    window.addEventListener("resize", adjustAnimationSpeed);
});
