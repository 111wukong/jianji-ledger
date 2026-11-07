/* 提前设置主题，避免样式加载时闪烁。外置以便服务端启用严格的 script-src 'self' CSP。 */
try {
  document.documentElement.dataset.theme = localStorage.getItem('jianji.theme') ||
    (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
} catch (e) {
  document.documentElement.dataset.theme = 'light';
}
