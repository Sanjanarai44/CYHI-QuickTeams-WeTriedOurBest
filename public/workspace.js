// Simple interactivity for the workspace page
document.addEventListener('DOMContentLoaded', function() {
  // Team card click handler
  const teamCards = document.querySelectorAll('.team-card');
  teamCards.forEach(card => {
    card.addEventListener('click', function() {
      // In a real app, this would navigate to the team page
      console.log('Team clicked:', this.querySelector('h3').textContent);
    });
  });
  
  // New team button handler
  const newTeamBtn = document.querySelector('.new-team-btn');
  if (newTeamBtn) {
    newTeamBtn.addEventListener('click', function() {
      // In a real app, this would open a modal or navigate to team creation
      console.log('Create new team clicked');
    });
  }
  
  // Profile button handler
  const profileBtn = document.querySelector('.profile-btn');
  if (profileBtn) {
    profileBtn.addEventListener('click', function() {
      // In a real app, this would navigate to the profile page
      console.log('Profile button clicked');
    });
  }
});