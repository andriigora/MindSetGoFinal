// Co-Edited by ChatGPT5
(() => {
  const NS = 'msg:scroll';
  const PATH = location.pathname;

  if ('scrollRestoration' in history) {
    history.scrollRestoration = 'manual';
  }

  const headerOffset = () => {
    const hdr = document.querySelector('.site-header');
    return hdr ? hdr.getBoundingClientRect().height + 8 : 0;
  };

  function saveState({ snapTop = null } = {}) {
    try {
      sessionStorage.setItem(`${NS}:path`, PATH);
      sessionStorage.setItem(`${NS}:y`, String(window.scrollY));
      if (snapTop != null) {
        sessionStorage.setItem(`${NS}:snapTop`, String(Math.max(0, snapTop)));
      } else {
        sessionStorage.removeItem(`${NS}:snapTop`);
      }
    } catch (_) {}
  }

  function closestSnapElement(from) {
    return (
      from.closest('li.habit') ||
      from.closest('section.card') ||
      from.closest('.container') ||
      document.scrollingElement
    );
  }

  document.addEventListener(
    'submit',
    (e) => {
      const host = closestSnapElement(e.target);
      const top = host
        ? host.getBoundingClientRect().top + window.scrollY
        : window.scrollY;
      saveState({ snapTop: top });
    },
    true // capture so it runs before navigation
  );

  document.addEventListener('click', (e) => {
    const a = e.target.closest('a');
    if (!a) return;
    const href = a.getAttribute('href') || '';
    if (
      href.startsWith('#') ||
      href.startsWith('javascript:') ||
      a.hasAttribute('download') ||
      a.target === '_blank'
    ) {
      return;
    }
    const host = closestSnapElement(a);
    const top = host
      ? host.getBoundingClientRect().top + window.scrollY
      : window.scrollY;
    saveState({ snapTop: top });
  });

  window.addEventListener('beforeunload', () => saveState({}));

  function restore() {
    try {
      const p = sessionStorage.getItem(`${NS}:path`);
      if (p !== PATH) return;

      const snap = sessionStorage.getItem(`${NS}:snapTop`);
      const y = sessionStorage.getItem(`${NS}:y`);
      const offset = headerOffset();

      if (snap != null) {
        const top = Math.max(0, parseFloat(snap) - offset);
        window.scrollTo({ top, behavior: 'auto' });
      } else if (y != null) {
        window.scrollTo({ top: Math.max(0, parseFloat(y)), behavior: 'auto' });
      }
    } finally {
      // one-shot
      sessionStorage.removeItem(`${NS}:snapTop`);
      sessionStorage.removeItem(`${NS}:y`);
      sessionStorage.removeItem(`${NS}:path`);
    }
  }
  window.addEventListener('load', () => {
    requestAnimationFrame(() => {
      requestAnimationFrame(restore);
    });
  });
})();
