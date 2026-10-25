(function () {
  var root = document.documentElement;
  var darkQuery = window.matchMedia('(prefers-color-scheme: dark)');

  function isDark() {
    var t = root.getAttribute('data-theme');
    return t ? t === 'dark' : darkQuery.matches;
  }

  // Theme toggle
  document.getElementById('theme-toggle').addEventListener('click', function () {
    var next = isDark() ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('theme', next); } catch (e) {}
    setShots(next);
  });

  // Screenshot light/dark tabs
  var tabs = document.querySelectorAll('.tab[data-shot]');
  function setShots(mode) {
    tabs.forEach(function (t) { t.setAttribute('aria-selected', String(t.dataset.shot === mode)); });
    document.querySelectorAll('img[data-light]').forEach(function (img) {
      img.src = img.dataset[mode];
    });
  }
  tabs.forEach(function (t) {
    t.addEventListener('click', function () { setShots(t.dataset.shot); });
  });
  setShots(isDark() ? 'dark' : 'light');

  // Label table cells with their column header (used by the stacked mobile layout)
  document.querySelectorAll('.table-wrap table').forEach(function (table) {
    var headers = Array.prototype.map.call(table.querySelectorAll('thead th'), function (th) {
      return th.textContent;
    });
    table.querySelectorAll('tbody tr').forEach(function (tr) {
      Array.prototype.forEach.call(tr.children, function (td, i) {
        td.setAttribute('data-label', headers[i] || '');
      });
    });
  });

  // Copy buttons on code blocks
  document.querySelectorAll('pre').forEach(function (pre) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy-btn';
    btn.textContent = 'Copy';
    btn.addEventListener('click', function () {
      var text = pre.querySelector('code').innerText;
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = 'Copied';
        setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
      });
    });
    pre.appendChild(btn);
  });

  // Highlight the current docs section in the sidebar
  var links = document.querySelectorAll('.toc a');
  var map = {};
  links.forEach(function (a) { map[a.getAttribute('href').slice(1)] = a; });
  if ('IntersectionObserver' in window) {
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          links.forEach(function (a) { a.classList.remove('active'); });
          map[entry.target.id].classList.add('active');
        }
      });
    }, { rootMargin: '-80px 0px -70% 0px' });
    Object.keys(map).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) observer.observe(el);
    });
  }
})();
