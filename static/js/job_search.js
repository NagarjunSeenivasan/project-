document.getElementById('filterBtn').addEventListener('click', function() {
    // Get filter values
    const roleFilter = document.getElementById('roleFilter').value.toLowerCase();
    const locationFilter = document.getElementById('locationFilter').value.toLowerCase();
    const skillFilter = document.getElementById('skillFilter').value.toLowerCase();
  
    // Get all job cards
    const jobCards = document.querySelectorAll('.job-card');
  
    // Loop through each job card and check if it matches the filters
    jobCards.forEach(card => {
      const role = card.getAttribute('data-role').toLowerCase();
      const location = card.getAttribute('data-location').toLowerCase();
      const skills = card.getAttribute('data-skill').toLowerCase();
  
      // Check if the job card matches all filter criteria
      const matchesRole = role.includes(roleFilter);
      const matchesLocation = location.includes(locationFilter);
      const matchesSkills = skills.includes(skillFilter);
  
      // Show or hide job card based on the filter match
      if (matchesRole && matchesLocation && matchesSkills) {
        card.style.display = 'flex'; // Show the card
      } else {
        card.style.display = 'none'; // Hide the card
      }
    });
  });
  