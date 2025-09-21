// Add copy-to-clipboard functionality to all copy buttons
document.querySelectorAll('.copy-btn').forEach(button => {
  button.addEventListener('click', () => {
    const codeBlock = button.previousElementSibling.querySelector('code');
    if (!codeBlock) return;
    
    const text = codeBlock.innerText;
    navigator.clipboard.writeText(text).then(() => {
      button.innerText = 'Copied!';
      setTimeout(() => button.innerText = 'Copy', 1500);
    }).catch(err => {
      console.error('Failed to copy:', err);
      button.innerText = 'Failed';
      setTimeout(() => button.innerText = 'Copy', 1500);
    });
  });
});
