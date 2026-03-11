document.addEventListener('DOMContentLoaded', () => {
  const groupSizeSelect = document.getElementById('group-size');
  const membersGrid = document.getElementById('members-grid');

  if (!groupSizeSelect || !membersGrid) return;

  function createMemberFields(groupSize) {
    membersGrid.innerHTML = '';

    for (let i = 1; i <= groupSize; i++) {
      const memberCard = document.createElement('div');
      memberCard.classList.add('leader-member-card');

      const memberTitle = document.createElement('h4');
      memberTitle.textContent = `Member ${i}`;
      memberCard.appendChild(memberTitle);

      const memberFields = document.createElement('div');
      memberFields.classList.add('leader-member-fields');

      const nameField = document.createElement('div');
      nameField.classList.add('leader-form-field');
      nameField.innerHTML = `
        <label for="leader-member-name-${i}">Name</label>
        <input type="text" id="leader-member-name-${i}" name="members[${i - 1}][name]" placeholder="Member ${i}'s name" required>
      `;
      memberFields.appendChild(nameField);

      const emailField = document.createElement('div');
      emailField.classList.add('leader-form-field');
      emailField.innerHTML = `
        <label for="leader-member-email-${i}">Email</label>
        <input type="email" id="leader-member-email-${i}" name="members[${i - 1}][email]" placeholder="Member ${i}'s email" required>
      `;
      memberFields.appendChild(emailField);

      memberCard.appendChild(memberFields);
      membersGrid.appendChild(memberCard);
    }
  }

  groupSizeSelect.addEventListener('change', (event) => {
    const groupSize = parseInt(event.target.value, 10);
    if (!isNaN(groupSize) && groupSize >= 2 && groupSize <= 10) {
      createMemberFields(groupSize);
    } else {
      membersGrid.innerHTML = '';
    }
  });

  // Render immediately if a value is already selected
  const initialGroupSize = parseInt(groupSizeSelect.value, 10);
  if (!isNaN(initialGroupSize) && initialGroupSize >= 2 && initialGroupSize <= 10) {
    createMemberFields(initialGroupSize);
  }
});