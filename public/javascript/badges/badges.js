document.addEventListener('DOMContentLoaded', function() {
  const badgeButtons = document.querySelectorAll('.badge-pick-btn');
  
  badgeButtons.forEach(button => {
    button.addEventListener('click', function() {
      // Get the badge image src from the same badge card.
      const badgeCard = this.closest('.badge-card');
      const badgeImg = badgeCard.querySelector('img');
      const badgePath = badgeImg.getAttribute('src');
      
      // Prompt the user for a badge name.
      const badgeName = prompt('give your badge a name');
      if (!badgeName) {
        alert('Badge name is required.');
        return;
      }
      
      const data = { badgePath, badgeName };
      
      // Send a POST request to store the badge in the session.
      fetch('/badges/pick', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      })
      .then(response => response.json())
      .then(result => {
        if (result.success) {
          // Redirect back to the prompt set form.
          window.location.href = '/unitform/form_promptset';
        } else {
          alert('Error: ' + result.error);
        }
      })
      .catch(error => {
        console.error('Error:', error);
      });
    });
  });
});
