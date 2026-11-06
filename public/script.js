const THEME_ICON = {
  dark: '<svg class="ico" aria-hidden="true"><use href="/icons.svg#sun"/></svg>',
  light: '<svg class="ico" aria-hidden="true"><use href="/icons.svg#moon"/></svg>'
};
const toggle = document.getElementById('theme-toggle');
if (toggle) {
  const currentTheme = localStorage.getItem('theme') || 
                       (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', currentTheme);
  toggle.innerHTML = currentTheme === 'dark' ? THEME_ICON.dark : THEME_ICON.light;

  toggle.addEventListener('click', () => {
    const theme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    toggle.innerHTML = theme === 'dark' ? THEME_ICON.dark : THEME_ICON.light;
  });
}