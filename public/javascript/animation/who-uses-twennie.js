const professions = [
    "architects",
    "services marketers",
    "engineers",
    "project managers",
    "interior designers",
    "technologists",
    "web designers",
    "app developers",
    "proposal managers",
    "CAD professionals",
    "urban planners",
  ];
  
  let currentProfessionIndex = 0;
  
  function updateDynamicWords() {
    const container = document.querySelector(".dynamic-text-container");
    const currentWord = document.querySelector(".dynamic-words");
    
    // Create new word element
    const newWord = document.createElement("span");
    newWord.className = "dynamic-words slide-down";
    newWord.textContent = professions[currentProfessionIndex];
    
    // Slide current word up
    currentWord.classList.add("slide-up");
    
    // After current word starts sliding up
    setTimeout(() => {
      // Add new word
      container.appendChild(newWord);
      
      // Trigger reflow
      newWord.offsetHeight;
      
      // Start sliding new word in
      newWord.classList.remove("slide-down");
      
      // Remove old word after animation
      setTimeout(() => {
        currentWord.remove();
      }, 800);
      
      // Update index for next iteration
      currentProfessionIndex = (currentProfessionIndex + 1) % professions.length;
    }, 800);
  }
  
  // Start the animation after a brief delay
  setTimeout(() => {
    updateDynamicWords();
    setInterval(updateDynamicWords, 3000);
  }, 1000);