document.getElementById('toggleContribute').addEventListener('click', function() {
    const grid = document.getElementById('contributionGrid');
    grid.style.display = grid.style.display === 'none' ? 'grid' : 'none';
});