(function () {
  const sidebar = document.getElementById('sidebar');
  const sidebarNav = document.getElementById('sidebarNav');
  const content = document.getElementById('content');
  const overlay = document.getElementById('overlay');
  const menuToggle = document.getElementById('menuToggle');
  const themeToggle = document.getElementById('themeToggle');
  const html = document.documentElement;

  let categories = null;
  let currentFile = null;

  function initTheme() {
    const saved = localStorage.getItem('theme');
    if (saved) {
      html.setAttribute('data-theme', saved);
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
      html.setAttribute('data-theme', 'dark');
    }
    updateThemeIcon();
  }

  function toggleTheme() {
    const current = html.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateThemeIcon();
  }

  function updateThemeIcon() {
    themeToggle.textContent = html.getAttribute('data-theme') === 'dark' ? '☀' : '🌙';
  }

  function toggleMenu() {
    sidebar.classList.toggle('open');
    overlay.classList.toggle('open');
    document.body.style.overflow = sidebar.classList.contains('open') ? 'hidden' : '';
  }

  function closeMenu() {
    sidebar.classList.remove('open');
    overlay.classList.remove('open');
    document.body.style.overflow = '';
  }

  themeToggle.addEventListener('click', toggleTheme);
  menuToggle.addEventListener('click', toggleMenu);
  overlay.addEventListener('click', closeMenu);

  async function loadCategories() {
    try {
      const resp = await fetch('categories.json');
      if (!resp.ok) throw new Error('Failed to load categories');
      categories = await resp.json();
      renderSidebar();
      handleRoute();
    } catch (err) {
      console.error(err);
      sidebarNav.innerHTML = '<p style="padding:1rem;color:var(--text-secondary)">Failed to load categories.</p>';
    }
  }

  function renderSidebar() {
    const sections = [
      { key: 'tops_100', title: 'Top 100' },
      { key: 'tops_by_bug_type', title: 'By Bug Type' },
      { key: 'tops_by_program', title: 'By Program' },
    ];

    sidebarNav.innerHTML = '';

    sections.forEach(function (section) {
      const items = categories[section.key] || [];
      if (items.length === 0) return;

      const div = document.createElement('div');
      div.className = 'sidebar-section';

      const titleBtn = document.createElement('button');
      titleBtn.className = 'sidebar-section-title';
      titleBtn.innerHTML = '<span>' + section.title + '</span><span class="arrow">▼</span>';
      titleBtn.addEventListener('click', function () {
        div.classList.toggle('collapsed');
      });

      const ul = document.createElement('ul');
      ul.className = 'sidebar-items';

      items.forEach(function (item) {
        const li = document.createElement('li');
        const btn = document.createElement('button');
        btn.className = 'sidebar-item';
        btn.textContent = item.name;
        btn.addEventListener('click', function () {
          loadFile(item.file, item.name);
          closeMenu();
        });
        btn.dataset.file = item.file;
        li.appendChild(btn);
        ul.appendChild(li);
      });

      div.appendChild(titleBtn);
      div.appendChild(ul);
      sidebarNav.appendChild(div);
    });
  }

  function setActive(file) {
    currentFile = file;
    var items = sidebarNav.querySelectorAll('.sidebar-item');
    items.forEach(function (item) {
      if (item.dataset.file === file) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });
  }

  async function loadFile(file, name) {
    content.innerHTML = '<div class="content-loading">Loading...</div>';
    window.location.hash = file;

    try {
      var resp = await fetch(file);
      if (!resp.ok) throw new Error('Failed to load: ' + file);
      var md = await resp.text();
      var html = parseMarkdown(md);
      content.innerHTML = '<div class="report-content">' + html + '</div>';
      setActive(file);
    } catch (err) {
      content.innerHTML = '<div class="content-error">' + err.message + '</div>';
      console.error(err);
    }
  }

  function parseMarkdown(md) {
    var lines = md.split('\n');
    var result = '';
    var inList = false;
    var i = 0;

    while (i < lines.length) {
      var line = lines[i];

      if (/^\d+\.\s/.test(line)) {
        if (!inList) {
          result += '<ol>';
          inList = true;
        }
        var content_text = line.replace(/^\d+\.\s/, '');

        var match = content_text.match(/^\[(.+)\]\((.+)\)\s+to\s+(.+?)\s+[—–-]\s+(.+)$/);
        var reportInfo = '';
        var titlePart = content_text;

        var titleText;
        if (match) {
          titleText = '<a href="' + match[2] + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(match[1]) + '</a>';
          reportInfo = ' <span class="report-meta">to <span class="report-program">' + escapeHtml(match[3]) + '</span> &mdash; ' + formatStats(match[4]) + '</span>';
        } else {
          titleText = convertLinks(titlePart);
        }
        result += '<li>' + titleText + reportInfo + '</li>';
      } else {
        if (inList) {
          result += '</ol>';
          inList = false;
        }
        if (line === '') {
          i++;
          continue;
        }
        if (/^#+\s/.test(line)) {
          var level = line.match(/^(#+)\s/)[1].length;
          var text = line.replace(/^#+\s/, '');
          result += '<h' + level + '>' + convertLinks(text) + '</h' + level + '>';
        } else {
          result += '<p>' + convertLinks(line) + '</p>';
        }
      }
      i++;
    }

    if (inList) {
      result += '</ol>';
    }

    return result;
  }

  function convertLinks(text) {
    return text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, function (_, label, url) {
      return '<a href="' + url + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(label) + '</a>';
    });
  }

  function formatStats(stats) {
    var upvotesMatch = stats.match(/(\d+)\s*upvotes?/);
    var bountyMatch = stats.match(/\$(\d[\d,]*)/);

    var parts = [];
    if (upvotesMatch) {
      parts.push('<span class="report-upvotes">' + upvotesMatch[1] + ' upvotes</span>');
    }
    if (bountyMatch) {
      parts.push('<span class="report-bounty">$' + bountyMatch[1].replace(/,+$/, '') + '</span>');
    }
    return parts.join(', ');
  }

  function escapeHtml(text) {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function handleRoute() {
    var hash = window.location.hash.replace('#', '');
    if (!hash || !categories) return;

    var allSections = Object.values(categories).flat();
    var found = allSections.find(function (item) { return item.file === hash; });
    if (found) {
      loadFile(found.file, found.name);
    }
  }

  window.addEventListener('hashchange', handleRoute);

  initTheme();
  loadCategories();
})();
