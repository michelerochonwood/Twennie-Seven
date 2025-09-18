document.addEventListener("DOMContentLoaded", function () {
    const assignForm = document.getElementById("assignPromptSetForm");
    const errorContainer = document.getElementById("assignPromptSetError");

    if (assignForm) {
        assignForm.addEventListener("submit", async function (event) {
            event.preventDefault();

            const formData = new FormData(assignForm);
            const jsonData = Object.fromEntries(formData.entries());

            // Ensure multiple selection is handled correctly
            jsonData.assignedMemberIds = Array.from(formData.getAll("assignedMemberIds"));

            try {
                const response = await fetch(assignForm.action, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(jsonData),
                });

                const result = await response.json();

                if (!result.success) {
                    errorContainer.textContent = result.errorMessage;
                    errorContainer.style.display = "block"; // Show error message
                } else {
                    window.location.href = result.redirectUrl; // Redirect on success
                }
            } catch (error) {
                console.error("Error submitting form:", error);
                errorContainer.textContent = "An unexpected error occurred. Please try again.";
                errorContainer.style.display = "block";
            }
        });
    }
});
