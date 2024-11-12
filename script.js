document.addEventListener("DOMContentLoaded", function() {
  const messages = [
    " who am i ? ",
    " Control is an illusion ... ",
    " kqvhhiehvbbhbiuhkivhjbg",
    " leave me here pls !!"
  ];
  
  const typingElement = document.getElementById("typing");
  let messageIndex = 0;
  let charIndex = 0;
  let isDeleting = false;

  function type() {
    const currentMessage = messages[messageIndex];
    
    if (!isDeleting && charIndex < currentMessage.length) {
      // Ajoute un caractère à la fois
      typingElement.textContent += currentMessage.charAt(charIndex);
      charIndex++;
      setTimeout(type, 100); // Vitesse de saisie
    } else if (isDeleting && charIndex > 0) {
      // Supprime un caractère à la fois
      typingElement.textContent = currentMessage.substring(0, charIndex - 1);
      charIndex--;
      setTimeout(type, 50); // Vitesse de suppression
    } else if (charIndex === currentMessage.length) {
      // Si on est au dernier message, on attend plus longtemps avant de supprimer
      const delay = (messageIndex === messages.length - 1) ? 7000 : 1000; // 3 secondes pour le dernier
      isDeleting = true;
      setTimeout(type, delay);
    } else if (isDeleting && charIndex === 0) {
      // Passe au message suivant après avoir tout effacé
      isDeleting = false;
      messageIndex = (messageIndex + 1) % messages.length; // Boucle sur les messages
      setTimeout(type, 500); // Temps d'attente avant de taper le prochain message
    }
  }

  type();
});