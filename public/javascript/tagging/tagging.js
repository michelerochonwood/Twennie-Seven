async function tagUnit(event) {
    event.preventDefault(); // ✅ Prevent page reload

    const unitId = document.getElementById('unitId').value;
    const unitType = document.getElementById('unitType').value;
    const csrfToken = document.querySelector('input[name="_csrf"]').value;

    // ✅ SweetAlert2 prompt for tag name
    const { value: tagName } = await Swal.fire({
        title: "Enter a Tag Name",
        input: "text",
        inputPlaceholder: "Enter a tag name...",
        showCancelButton: true,
        confirmButtonColor: "#262262",
        cancelButtonColor: "#e0e0e0",
        confirmButtonText: "Tag",
        cancelButtonText: "Cancel",
        inputValidator: (value) => {
            if (!value) return "Tag name is required!";
        },
        customClass: {
            popup: "swal2-popup",
            title: "swal2-title",
            confirmButton: "swal2-confirm",
            cancelButton: "swal2-cancel"
        }
    });

    if (!tagName) return; // ✅ Stop if no tag is entered

    try {
        const response = await fetch('/tags/create', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken  // ✅ Include CSRF token in the headers
            },
            body: JSON.stringify({
                name: tagName,
                itemId: unitId,
                itemType: unitType,
                _csrf: csrfToken  // ✅ Include CSRF token in request body
            })
        });

        const data = await response.json();

        if (response.ok) {
            Swal.fire({
                title: "Tagged Successfully!",
                text: `"${tagName}" has been added to your saved tags.`,
                icon: "success",
                confirmButtonColor: "#262262"
            });
        } else {
            Swal.fire({
                title: "Error",
                text: data.message || "An error occurred while tagging.",
                icon: "error",
                confirmButtonColor: "#ff4d4d"
            });
        }
    } catch (error) {
        Swal.fire({
            title: "Error",
            text: "Failed to tag the topic. Please try again later.",
            icon: "error",
            confirmButtonColor: "#ff4d4d"
        });
    }
}


