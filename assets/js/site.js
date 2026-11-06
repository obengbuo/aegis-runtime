/* aegis.runtime — shared behaviour. No dependencies, progressive enhancement only:
   every page is fully readable with this file blocked. */
(function () {
  'use strict';

  var root = document.documentElement;

  function store(key, value) {
    try {
      if (value === undefined) return localStorage.getItem(key);
      if (value === null) localStorage.removeItem(key); else localStorage.setItem(key, value);
    } catch (e) { return null; }
  }

  /* ---- Theme toggle (initial value is set by an inline script in <head>) ---- */
  var themeBtn = document.querySelector('.theme-toggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      var current = root.getAttribute('data-theme') ||
        (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
      var next = current === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      store('aegis-theme', next);
      themeBtn.setAttribute('aria-label', next === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    });
  }

  /* ---- Mobile navigation ---- */
  var menuBtn = document.querySelector('.menu-toggle');
  if (menuBtn) {
    var closeMenu = function () {
      document.body.classList.remove('nav-open');
      menuBtn.setAttribute('aria-expanded', 'false');
    };
    menuBtn.addEventListener('click', function () {
      var open = document.body.classList.toggle('nav-open');
      menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeMenu(); });
    document.querySelectorAll('.site-nav a').forEach(function (a) { a.addEventListener('click', closeMenu); });
    window.addEventListener('resize', function () { if (window.innerWidth > 940) closeMenu(); });
  }

  /* ---- Copy buttons on code panels ---- */
  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var target = btn.getAttribute('data-copy');
      var el = target ? document.getElementById(target) : btn.closest('.panel').querySelector('pre');
      if (!el) return;
      var text = el.innerText.replace(/ /g, ' ').replace(/\s+$/, '') + '\n';
      var done = function () {
        btn.textContent = 'copied';
        btn.classList.add('copied');
        setTimeout(function () { btn.textContent = 'copy'; btn.classList.remove('copied'); }, 1600);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
      } else { fallbackCopy(text); done(); }
    });
  });
  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (e) { /* nothing else to try */ }
    document.body.removeChild(ta);
  }

  /* ---- Heading anchors + table of contents ---- */
  var prose = document.querySelector('.prose[data-toc]');
  if (prose) {
    var toc = document.querySelector('.toc');
    var heads = prose.querySelectorAll('h2, h3');
    var links = [];
    heads.forEach(function (h) {
      if (!h.id) {
        h.id = h.textContent.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      }
      var a = document.createElement('a');
      a.className = 'anchor'; a.href = '#' + h.id; a.setAttribute('aria-label', 'Link to this section');
      a.textContent = '#';
      h.appendChild(a);
      if (toc && h.tagName === 'H2') {
        var l = document.createElement('a');
        l.href = '#' + h.id;
        l.textContent = h.childNodes[0].textContent.trim();
        toc.appendChild(l);
        links.push({ link: l, head: h });
      }
    });
    if (toc && links.length && 'IntersectionObserver' in window) {
      var setActive = function (id) {
        links.forEach(function (x) { x.link.classList.toggle('active', x.head.id === id); });
      };
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) { if (en.isIntersecting) setActive(en.target.id); });
      }, { rootMargin: '-15% 0px -70% 0px' });
      links.forEach(function (x) { io.observe(x.head); });
    }
    if (toc && !links.length) toc.style.display = 'none';
  }

  /* ---- Docs: mobile page picker ---- */
  var picker = document.querySelector('.docs-mobile-nav select');
  if (picker) picker.addEventListener('change', function () { window.location.href = picker.value; });

  /* ---- Reading progress (articles) ---- */
  var bar = document.querySelector('.reading-progress');
  var article = document.querySelector('article.prose');
  if (bar && article) {
    var update = function () {
      var r = article.getBoundingClientRect();
      var total = r.height - window.innerHeight * 0.6;
      var pct = Math.min(1, Math.max(0, -r.top / (total || 1)));
      bar.style.width = (pct * 100).toFixed(1) + '%';
    };
    window.addEventListener('scroll', update, { passive: true });
    update();
  }

  /* ---- Share: copy link ---- */
  document.querySelectorAll('[data-share-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var url = btn.getAttribute('data-share-copy') || window.location.href;
      var label = btn.textContent;
      var done = function () { btn.textContent = 'Link copied'; setTimeout(function () { btn.textContent = label; }, 1600); };
      if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(url).then(done, done);
      else { fallbackCopy(url); done(); }
    });
  });

  /* ---- Home: replay the run log once it scrolls into view ---- */
  var runlog = document.querySelector('.runlog');
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (runlog && !reduce && 'IntersectionObserver' in window) {
    var lines = runlog.querySelectorAll('.ln');
    runlog.classList.add('animate');
    var play = function () {
      lines.forEach(function (ln, i) { setTimeout(function () { ln.classList.add('on'); }, 180 + i * 260); });
    };
    // Never leave the log blank: if the observer hasn't fired (background tab, odd layout), show it all.
    setTimeout(function () { lines.forEach(function (ln) { ln.classList.add('on'); }); }, 4000);
    var seen = new IntersectionObserver(function (entries) {
      if (entries[0].isIntersecting) { play(); seen.disconnect(); }
    }, { threshold: 0.3 });
    seen.observe(runlog);
    var replay = document.querySelector('[data-replay]');
    if (replay) replay.addEventListener('click', function () {
      lines.forEach(function (ln) { ln.classList.remove('on'); });
      setTimeout(play, 200);
    });
  }

  /* ---- Filter chips (security page) ---- */
  document.querySelectorAll('[data-filter-group]').forEach(function (group) {
    var targetSel = group.getAttribute('data-filter-group');
    var chips = group.querySelectorAll('.chip');
    chips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        var f = chip.getAttribute('data-filter');
        chips.forEach(function (c) { c.setAttribute('aria-pressed', c === chip ? 'true' : 'false'); });
        document.querySelectorAll(targetSel).forEach(function (item) {
          item.hidden = !(f === 'all' || item.getAttribute('data-status') === f);
        });
      });
    });
  });

  /* ---- Contact form: compose a mailto (static site, no backend) ---- */
  var form = document.querySelector('form[data-mailto]');
  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var to = form.getAttribute('data-mailto');
      var topic = form.querySelector('[name=topic]').value;
      var name = form.querySelector('[name=name]').value.trim();
      var org = form.querySelector('[name=org]').value.trim();
      var msg = form.querySelector('[name=message]').value.trim();
      if (!msg) { form.querySelector('[name=message]').focus(); return; }
      var subject = '[Aegis] ' + topic + (org ? ' — ' + org : '');
      var body = msg + '\n\n— ' + (name || 'Sent from aegisruntime.dev') + (org ? ', ' + org : '');
      window.location.href = 'mailto:' + to + '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);
      var note = form.querySelector('.form-status');
      if (note) note.textContent = 'Your mail app should open with the message filled in. If it does not, write to ' + to + ' directly.';
    });
  }

  /* ---- Footer year ---- */
  var y = document.querySelector('[data-year]');
  if (y) y.textContent = new Date().getFullYear();
})();
