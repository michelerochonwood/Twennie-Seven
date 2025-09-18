console.log("📦 unregister.js loaded");
document.addEventListener("DOMContentLoaded", function () {
const unregisterButtons = document.querySelectorAll(
  ".groupmember-unregister-btn, .leader-unregister-btn, .member-unregister-btn"
);

    unregisterButtons.forEach(button => {
        button.addEventListener("click", async function () {
            const registrationId = this.dataset.id;

            console.log("🔍 Attempting to unregister ID:", registrationId);

            if (!registrationId) {
                Swal.fire({
                    icon: "error",
                    title: "Error",
                    text: "Registration ID is missing."
                });
                return;
            }

            const result = await Swal.fire({
                title: "Are you sure?",
                text: "You will be unregistered from this prompt set.",
                icon: "warning",
                showCancelButton: true,
                confirmButtonColor: "#d33",
                cancelButtonColor: "#3085d6",
                confirmButtonText: "Yes, unregister"
            });

            if (!result.isConfirmed) return;

            try {
                const response = await fetch(`/promptsetregistration/unregister/${registrationId}`, {
                    method: "DELETE",
                    headers: {
                        "Content-Type": "application/json"
                    }
                });

                if (response.ok) {
                    Swal.fire({
                        icon: "success",
                        title: "Unregistered!",
                        text: "You have successfully unregistered from the prompt set.",
                        timer: 2000,
                        showConfirmButton: false
                    }).then(() => location.reload());
                } else {
                    Swal.fire({
                        icon: "error",
                        title: "Error",
                        text: "Failed to unregister. Please try again."
                    });
                }
            } catch (error) {
                console.error("Error:", error);
                Swal.fire({
                    icon: "error",
                    title: "Error",
                    text: "An unexpected error occurred."
                });
            }
        });
    });
});



