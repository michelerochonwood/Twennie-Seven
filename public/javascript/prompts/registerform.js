function toggleRegisterForm() {
    const formContainer = document.getElementById("registerPromptSetFormContainer");
    formContainer.classList.toggle("hidden");
}

function registerPromptSet(event) {
    event.preventDefault();
    
    const form = document.getElementById("registerPromptSetForm");
    const formData = new FormData(form);
    
    fetch("/promptsetregistration/register", {
        method: "POST",
        body: formData,
        headers: {
            "X-Requested-With": "XMLHttpRequest"
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            alert(data.message);
            document.getElementById("registerPromptSetFormContainer").classList.add("hidden");
        }
    })
    .catch(error => {
        console.error("Error registering prompt set:", error);
        alert("An error occurred. Please try again.");
    });
}