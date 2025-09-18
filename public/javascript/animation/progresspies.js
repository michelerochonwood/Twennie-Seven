document.addEventListener("DOMContentLoaded", () => {
    const progressImages = document.querySelectorAll(".groupmember-progress-svg");

    progressImages.forEach(img => {
        let progressValue = parseInt(img.dataset.progress, 10) || 0;

        // Adjust spin duration: More progress = slower spin
        let duration = 1.5 + (progressValue / 10); // Example scaling

        img.style.animation = `spinProgress ${duration}s ease-out forwards`;
    });
});
