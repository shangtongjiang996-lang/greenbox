const toggle = document.getElementById('theme-toggle');
if (toggle) {
  const currentTheme = localStorage.getItem('theme') || 
                       (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', currentTheme);
  toggle.textContent = currentTheme === 'dark' ? '☀️' : '🌙';

  toggle.addEventListener('click', () => {
    const theme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    toggle.textContent = theme === 'dark' ? '☀️' : '🌙';
  });
}