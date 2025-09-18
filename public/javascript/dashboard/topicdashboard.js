document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".expand-arrow").forEach((arrow) => {
        arrow.addEventListener("click", function () {
            const content = this.nextElementSibling;
            content.classList.toggle("hidden");
            this.textContent = content.classList.contains("hidden") ? "▼" : "▲";
        });
    });
});