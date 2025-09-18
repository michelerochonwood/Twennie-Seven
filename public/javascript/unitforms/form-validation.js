document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("promptset-form");

    if (!form) return;

    // Attach character counters and validations for each prompt
    const setupPromptValidation = (promptId, min = 1, max = 1000) => {
        const textarea = document.getElementById(promptId);

        if (textarea) {
            const counter = document.createElement("small");
            counter.className = "character-count";
            counter.style.display = "block";
            counter.style.color = "#666";
            counter.textContent = `0/${max} characters`;
            textarea.parentNode.appendChild(counter);

            // Live character count update
            textarea.addEventListener("input", () => {
                const length = textarea.value.length;
                counter.textContent = `${length}/${max} characters`;

                if (length < min || length > max) {
                    counter.style.color = "red";
                } else {
                    counter.style.color = "#666";
                }
            });
        }
    };

    // Setup validation for each prompt
    for (let i = 1; i <= 20; i++) {
        setupPromptValidation(`Prompt${i}`);
    }

    // Form submission validation
    form.addEventListener("submit", (event) => {
        const errors = [];

        // Check required fields
        const checkRequiredField = (fieldId, fieldName) => {
            const field = form.querySelector(`[name="${fieldId}"]`);
            if (!field || field.value.trim() === "") {
                errors.push(`${fieldName} is required.`);
            }
        };

        checkRequiredField("promptset_title", "Prompt-set title");
        checkRequiredField("main_topic", "Main topic");
        checkRequiredField("short_summary", "Short summary");
        checkRequiredField("full_summary", "Full summary");

        // Check target audience
        const targetAudience = form.querySelector('input[name="target_audience"]:checked');
        if (!targetAudience) {
            errors.push("Target audience is required.");
        }

        // Check suggested frequency
        const suggestedFrequency = form.querySelector('#suggested_frequency');
        if (!suggestedFrequency || suggestedFrequency.value.trim() === "") {
            errors.push("Suggested frequency is required.");
        }

        // Automatically populate author ID
        const authorIdField = form.querySelector('[name="author.id"]');
        if (authorIdField) {
            authorIdField.value = window.loggedInUserId || ""; // Replace with dynamically injected logged-in user ID
        }

        if (!authorIdField || authorIdField.value.trim() === "") {
            errors.push("Author ID is required.");
        }

        // Check prompt validations explicitly
        const validatePrompt = (promptId) => {
            const textarea = document.getElementById(promptId);
            if (textarea) {
                const length = textarea.value.length;
                if (length < 1 || length > 1000) {
                    errors.push(`${promptId} must be between 1 and 1000 characters.`);
                }
            }
        };

        for (let i = 1; i <= 20; i++) {
            validatePrompt(`Prompt${i}`);
        }

        if (errors.length > 0) {
            event.preventDefault(); // Prevent form submission
            alert(errors.join("\n")); // Display all validation errors
        }
    });
});


  


  