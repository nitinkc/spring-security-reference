// Initialize mermaid on load with relaxed security to allow complex labels
window.addEventListener('load', function () {
  if (typeof mermaid !== 'undefined') {
    try {
      mermaid.initialize({
        startOnLoad: true,
        securityLevel: 'loose',
        theme: 'default',
        flowchart: { useMaxWidth: true },
        sequence: { mirrorActors: true }
      });
    } catch (e) {
      console.warn('Mermaid initialization failed:', e);
    }
  }
});
