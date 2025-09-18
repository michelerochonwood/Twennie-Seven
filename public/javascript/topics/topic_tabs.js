document.addEventListener("DOMContentLoaded", function () {
    const tabs = document.querySelectorAll(".topics-tab");
    const contents = document.querySelectorAll(".topics-tab-content");

    tabs.forEach((tab) => {
        tab.addEventListener("click", function () {
            // Remove active class from all tabs
            tabs.forEach(t => t.classList.remove("active"));
            // Hide all content
            contents.forEach(c => c.classList.remove("active"));

            // Add active class to clicked tab
            this.classList.add("active");

            // Show associated content
            const tabId = this.getAttribute("data-tab");
            document.getElementById(tabId).classList.add("active");
        });
    });
});
