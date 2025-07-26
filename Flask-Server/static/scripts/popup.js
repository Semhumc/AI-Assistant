

// Toggle sağ-sol menüler
  const leftNav = document.querySelector('.left');
  const rightNav = document.querySelector('.right');
  const toggleLeftBtn = document.getElementById('toggleLeftBtn');
  const toggleRightBtn = document.getElementById('toggleRightBtn');

  toggleLeftBtn.addEventListener('click', () => {
    leftNav.classList.toggle('hidden');
  });

  toggleRightBtn.addEventListener('click', () => {
    rightNav.classList.toggle('hidden');
  });
  function togglePopup(id) {
  const popups = ['notificationsPopup', 'profilePopup'];

  popups.forEach(popupId => {
    const popup = document.getElementById(popupId);
    if (popupId === id) {
      const isVisible = popup.style.display === 'block';
      popup.style.display = isVisible ? 'none' : 'block';
    } else {
      popup.style.display = 'none';
    }
  });
}

// Popup dışına tıklanınca kapat
document.addEventListener('click', function (event) {
  const popups = ['notificationsPopup', 'profilePopup'];
  let isClickInsidePopup = false;

  popups.forEach(popupId => {
    const popup = document.getElementById(popupId);
    const button = document.querySelector(`button[onclick*="${popupId}"]`);

    if (popup && (popup.contains(event.target) || button.contains(event.target))) {
      isClickInsidePopup = true;
    }
  });

  if (!isClickInsidePopup) {
    popups.forEach(popupId => {
      const popup = document.getElementById(popupId);
      if (popup) {
        popup.style.display = 'none';
      }
    });
  }
});
// Küçük ekranlarda açılışta sağ ve sol gizli olsun
  function checkWindowSize() {
    if(window.innerWidth <= 900){
      leftNav.classList.add('hidden');
      rightNav.classList.add('hidden');
    } else {
      leftNav.classList.remove('hidden');
      rightNav.classList.remove('hidden');
    }
  }
  window.addEventListener('resize', checkWindowSize);
  window.addEventListener('load', checkWindowSize);

function sendMessage() {
  const input = document.getElementById('userInput');
  const message = input.value.trim();
  if (message === "") return;

  const chatBox = document.getElementById('chatMessages');

  // Kullanıcı mesajı
  const userMessage = document.createElement('div');
  userMessage.className = 'message user';
  userMessage.textContent = message;
  chatBox.appendChild(userMessage);

  // Bot yanıtı
  const botReply = document.createElement('div');
  botReply.className = 'message bot';
  botReply.textContent = "🤖 Merhaba! Şu an sadece örnek mesaj verebiliyorum.";
  chatBox.appendChild(botReply);

  input.value = "";
  chatBox.scrollTop = chatBox.scrollHeight; // Otomatik kaydır
}
function goToUpdate(username) {
  window.location.href = `empupdate.html?username=${encodeURIComponent(username)}`;
}

function goToDelete(username) {
  window.location.href = `empdelete.html?username=${encodeURIComponent(username)}`;
}
