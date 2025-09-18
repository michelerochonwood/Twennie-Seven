document.addEventListener('DOMContentLoaded', () => {
    const groupSizeSelect = document.getElementById('group-size');
    const membersGrid = document.getElementById('members-grid');

    // Function to create member fields dynamically
    function createMemberFields(groupSize) {
        // Clear existing member fields
        membersGrid.innerHTML = '';

        for (let i = 1; i <= groupSize; i++) {
            // Create a card for each member's details
            const memberCard = document.createElement('div');
            memberCard.classList.add('leader-member-card'); // Unique class for leader form

            // Add a title for the member
            const memberTitle = document.createElement('h4');
            memberTitle.textContent = `Member ${i}`;
            memberCard.appendChild(memberTitle);

            // Create a container for the fields
            const memberFields = document.createElement('div');
            memberFields.classList.add('leader-member-fields'); // Unique class for leader form

            // Member name field
            const nameField = document.createElement('div');
            nameField.classList.add('leader-form-field'); // Unique class for leader form
            nameField.innerHTML = `
                <label for="leader-member-name-${i}">Name</label>
                <input type="text" id="leader-member-name-${i}" name="members[${i - 1}][name]" placeholder="Member ${i}'s name" required>
            `;
            memberFields.appendChild(nameField);

            // Member email field
            const emailField = document.createElement('div');
            emailField.classList.add('leader-form-field'); // Unique class for leader form
            emailField.innerHTML = `
                <label for="leader-member-email-${i}">Email</label>
                <input type="email" id="leader-member-email-${i}" name="members[${i - 1}][email]" placeholder="Member ${i}'s email" required>
            `;
            memberFields.appendChild(emailField);

            // Append the fields to the card
            memberCard.appendChild(memberFields);

            // Append the card to the grid
            membersGrid.appendChild(memberCard);
        }
    }

    // Event listener for changes in group size
    groupSizeSelect.addEventListener('change', (event) => {
        const groupSize = parseInt(event.target.value, 10);
        if (!isNaN(groupSize) && groupSize >= 2 && groupSize <= 10) {
            createMemberFields(groupSize);
        } else {
            membersGrid.innerHTML = ''; // Clear fields if an invalid size is selected
        }
    });
});