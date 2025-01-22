const crazyMessages = [
    "Right-click? Let's chat instead! 🗣️",
    "No shortcuts here, just good vibes! ✨",
    "Right-clicking won't connect you to the community, but posting will! 📢",
    "Want to connect? Start a discussion, not a right-click! 💬",
    "No need to hack the system, just join the convo! 🤝",
    "LOL! You can't unlock new friendships with right-clicks! 😂",
    "Stop right-clicking and share some thoughts in the community! 🌍",
    "This page is all about collaboration, not context menus! 👫",
    "Right-clicking won't earn you karma points! 🙌",
    "System says: 'Engage with the community, not the context menu!' 👥"
];

document.addEventListener('contextmenu', function (e) {
    e.preventDefault();
    const randomMessage = crazyMessages[Math.floor(Math.random() * crazyMessages.length)];
    document.getElementById('crazyMessageBody').innerText = randomMessage;
    
    const crazyModal = new bootstrap.Modal(document.getElementById('crazyMessageModal'));
    crazyModal.show();

    // Auto-close modal after 3 seconds
    setTimeout(() => {
        crazyModal.hide();
    }, 3000);
});
