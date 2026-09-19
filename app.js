const STORAGE_PREFIX = 'security-feed-v1';
const PAGE_SIZE = 24;
const DAY = 24 * 60 * 60 * 1000;
const LABELS = {
  alert: '注意喚起',
  vulnerability: '脆弱性',
  exploited: '悪用確認',
  analysis: '分析・レポート',
  blog: 'ブログ',
  community: 'Reddit の話題',
  exploit: '公開PoC',
};

const state = {
  items: [],
  sources: [],
  category: 'all',
  source: 'all',
  period: 7,
  search: '',
  unreadOnly: false,
  savedOnly: false,
  visible: PAGE_SIZE,
  read: loadSet('read'),
  saved: loadSet('saved'),
};

function loadSet(name) {
  try {
    const value = JSON.parse(localStorage.getItem(`${STORAGE_PREFIX}-${name}`) || '[]');
    return new Set(Array.isArray(value) ? value.filter((item) => typeof item === 'string') : []);
  } catch {
    return new Set();
  }
}

function saveSet(name, values) {
  try {
    localStorage.setItem(`${STORAGE_PREFIX}-${name}`, JSON.stringify([...values].slice(-1500)));
  } catch {
    // Reading still works if browser storage is unavailable.
  }
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function safeUrl(value) {
  try {
    const url = new URL(value);
    return ['https:', 'http:'].includes(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}

function jstDate(value, detailed = false) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '日時不明';
  return new Intl.DateTimeFormat('ja-JP', {
    timeZone: 'Asia/Tokyo', year: 'numeric', month: '2-digit', day: '2-digit',
    ...(detailed ? { hour: '2-digit', minute: '2-digit' } : {}),
  }).format(date);
}

function relativeDate(value) {
  const diff = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(diff) || diff < 0) return jstDate(value);
  if (diff < 60 * 60 * 1000) return `${Math.max(1, Math.floor(diff / 60000))}分前`;
  if (diff < DAY) return `${Math.floor(diff / 3600000)}時間前`;
  if (diff < 2 * DAY) return '昨日';
  return jstDate(value);
}

function sourceName(id) {
  return state.sources.find((source) => source.id === id)?.name || id;
}

function isImportant(item) {
  return item.priority === 'urgent' || item.priority === 'exploited' || item.priority === 'exploit-published';
}

function markRead(id) {
  state.read.add(id);
  saveSet('read', state.read);
  renderFeed();
  renderExploitWatch();
}

function toggleSaved(id) {
  if (state.saved.has(id)) state.saved.delete(id);
  else state.saved.add(id);
  saveSet('saved', state.saved);
  renderFeed();
  renderPriority();
  renderExploitWatch();
}

function badge(label, variant) {
  return el('span', `badge badge-${variant}`, label);
}

function articleLink(item, label, className) {
  const href = safeUrl(item.url);
  const link = el('a', className, label);
  if (href) {
    link.href = href;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.addEventListener('click', () => markRead(item.id));
  } else {
    link.removeAttribute('href');
  }
  return link;
}

function renderPriority() {
  const target = document.querySelector('#priority-grid');
  target.replaceChildren();
  const cutoff = Date.now() - 7 * DAY;
  const urgentCutoff = Date.now() - 30 * DAY;
  const relevant = state.items.filter((item) => (item.priority === 'urgent' && new Date(item.publishedAt).getTime() >= urgentCutoff)
    || (item.priority === 'exploited' && new Date(item.publishedAt).getTime() >= cutoff));
  relevant.sort((a, b) => (a.priority === 'urgent' ? -1 : 0) - (b.priority === 'urgent' ? -1 : 0) || new Date(b.publishedAt) - new Date(a.publishedAt));
  const selected = [];
  const perSource = new Map();
  for (const item of relevant) {
    if ((perSource.get(item.source) || 0) >= 2) continue;
    selected.push(item);
    perSource.set(item.source, (perSource.get(item.source) || 0) + 1);
    if (selected.length === 3) break;
  }
  if (!selected.length) {
    target.append(el('div', 'empty-priority', '過去7日に該当する重要な更新はありません。'));
    return;
  }
  for (const item of selected) {
    const card = el('article', 'priority-card');
    const top = el('div', 'priority-card-top');
    top.append(badge(item.priority === 'urgent' ? '緊急' : '悪用確認', item.priority));
    top.append(el('span', 'card-date', relativeDate(item.publishedAt)));
    card.append(top);
    card.append(articleLink(item, item.title, 'priority-title'));
    if (item.description) card.append(el('p', 'priority-description', item.description));
    const bottom = el('div', 'priority-bottom');
    bottom.append(el('span', '', sourceName(item.source)));
    bottom.append(articleLink(item, '原文を読む ↗', 'priority-read'));
    card.append(bottom);
    target.append(card);
  }
}

function renderExploitWatch() {
  const target = document.querySelector('#exploit-list');
  target.replaceChildren();
  const cutoff = Date.now() - 30 * DAY;
  const items = state.items.filter((item) => item.source === 'exploit-db' && new Date(item.publishedAt).getTime() >= cutoff).slice(0, 4);
  if (!items.length) {
    target.append(el('p', 'exploit-empty', '直近30日の登録・更新はありません。取得状況は情報源欄で確認できます。'));
    return;
  }
  for (const item of items) target.append(feedCard(item));
}

function filteredItems() {
  const cutoff = Date.now() - state.period * DAY;
  const query = state.search.trim().toLocaleLowerCase();
  return state.items.filter((item) => {
    if (new Date(item.publishedAt).getTime() < cutoff) return false;
    if (state.category === 'important' && !isImportant(item)) return false;
    if (state.category !== 'all' && state.category !== 'important' && item.category !== state.category) return false;
    if (state.source !== 'all' && item.source !== state.source) return false;
    if (state.unreadOnly && state.read.has(item.id)) return false;
    if (state.savedOnly && !state.saved.has(item.id)) return false;
    if (query && !`${item.title} ${item.description} ${(item.cves || []).join(' ')} ${sourceName(item.source)}`.toLocaleLowerCase().includes(query)) return false;
    return true;
  });
}

function feedCard(item) {
  const card = el('article', `feed-card${state.read.has(item.id) ? ' is-read' : ''}`);
  const marker = el('span', 'unread-marker');
  marker.setAttribute('aria-label', state.read.has(item.id) ? '既読' : '未読');
  card.append(marker);
  const body = el('div', 'feed-card-body');
  const meta = el('div', 'feed-meta');
  meta.append(el('span', 'source-label', sourceName(item.source)));
  meta.append(el('span', 'meta-separator', '·'));
  meta.append(el('span', '', LABELS[item.category] || '情報'));
  meta.append(el('span', 'meta-separator', '·'));
  const time = el('time', '', relativeDate(item.publishedAt));
  time.dateTime = item.publishedAt;
  time.title = jstDate(item.publishedAt, true);
  meta.append(time);
  body.append(meta);
  body.append(articleLink(item, item.title, 'feed-title'));
  if (item.description) body.append(el('p', 'feed-description', item.description));
  const tags = el('div', 'feed-tags');
  if (item.priority === 'urgent') tags.append(badge('緊急', 'urgent'));
  if (item.priority === 'exploited') tags.append(badge('悪用確認', 'exploited'));
  if (item.priority === 'exploit-published') tags.append(badge('PoC公開', 'exploit-published'));
  if (item.category === 'community') tags.append(badge('週間上位', 'community'));
  for (const cve of (item.cves || []).slice(0, 3)) tags.append(el('span', 'cve-tag', cve));
  if (tags.childNodes.length) body.append(tags);
  card.append(body);
  const actions = el('div', 'feed-actions');
  const save = el('button', `save-button${state.saved.has(item.id) ? ' is-saved' : ''}`, state.saved.has(item.id) ? '★' : '☆');
  save.type = 'button';
  save.title = state.saved.has(item.id) ? '保存を解除' : 'あとで読むため保存';
  save.setAttribute('aria-label', save.title);
  save.setAttribute('aria-pressed', String(state.saved.has(item.id)));
  save.addEventListener('click', () => toggleSaved(item.id));
  actions.append(save);
  actions.append(articleLink(item, '↗', 'open-link'));
  card.append(actions);
  return card;
}

function renderFeed() {
  const target = document.querySelector('#feed-list');
  const matches = filteredItems();
  document.querySelector('#result-count').textContent = `${matches.length} 件`;
  target.replaceChildren();
  if (!matches.length) {
    const empty = el('div', 'empty-feed');
    empty.append(el('strong', '', state.items.length ? '条件に合う記事がありません' : '記事データを準備中です'));
    empty.append(el('p', '', state.items.length ? '期間や絞り込みを変更してください。' : '情報源の取得後、ここに最新記事が表示されます。'));
    target.append(empty);
  } else {
    const fragment = document.createDocumentFragment();
    for (const item of matches.slice(0, state.visible)) fragment.append(feedCard(item));
    target.append(fragment);
  }
  document.querySelector('#load-more').hidden = matches.length <= state.visible;
}

function renderSources() {
  const list = document.querySelector('#source-list');
  list.replaceChildren();
  for (const source of state.sources) {
    const row = el('div', 'source-row');
    const dot = el('span', `source-dot${source.ok ? '' : ' source-error'}`);
    dot.setAttribute('aria-label', source.ok ? '取得成功' : '取得失敗');
    row.append(dot);
    const link = el('a', '', source.name);
    const href = safeUrl(source.home);
    if (href) {
      link.href = href;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
    }
    row.append(link);
    row.append(el('span', 'source-arrow', '↗'));
    list.append(row);
  }
  const failed = state.sources.filter((source) => !source.ok);
  document.querySelector('#update-status').textContent = failed.length
    ? `${failed.map((source) => source.name).join('、')} の取得に失敗しました。前回の情報を表示しています。`
    : `すべての情報源を確認済み。最終確認: ${state.checkedAt ? jstDate(state.checkedAt, true) : '未更新'}`;
}

function renderSummary() {
  const now = Date.now();
  const recent = state.items.filter((item) => new Date(item.publishedAt).getTime() >= now - 7 * DAY);
  document.querySelector('#count-week').textContent = recent.length.toLocaleString('ja-JP');
  document.querySelector('#count-today').textContent = state.items.filter((item) => new Date(item.publishedAt).getTime() >= now - DAY).length.toLocaleString('ja-JP');
  document.querySelector('#count-priority').textContent = recent.filter(isImportant).length.toLocaleString('ja-JP');
  document.querySelector('#count-sources').textContent = state.sources.length.toLocaleString('ja-JP');
  document.querySelector('#hero-update').textContent = state.checkedAt ? `最終確認 ${jstDate(state.checkedAt, true)} JST` : '初回更新を待っています';
  document.querySelector('#header-date').textContent = new Intl.DateTimeFormat('ja-JP', { timeZone: 'Asia/Tokyo', year: 'numeric', month: 'long', day: 'numeric' }).format(now);
}

function setupControls() {
  document.querySelector('#search-input').addEventListener('input', (event) => {
    state.search = event.target.value;
    state.visible = PAGE_SIZE;
    renderFeed();
  });
  document.querySelector('#period-select').addEventListener('change', (event) => {
    state.period = Number(event.target.value);
    state.visible = PAGE_SIZE;
    renderFeed();
  });
  document.querySelector('#source-select').addEventListener('change', (event) => {
    state.source = event.target.value;
    state.visible = PAGE_SIZE;
    renderFeed();
  });
  document.querySelector('#category-tabs').addEventListener('click', (event) => {
    const button = event.target.closest('button[data-category]');
    if (!button) return;
    state.category = button.dataset.category;
    state.visible = PAGE_SIZE;
    for (const tab of document.querySelectorAll('#category-tabs button')) {
      const selected = tab === button;
      tab.classList.toggle('active', selected);
      tab.setAttribute('aria-pressed', String(selected));
    }
    renderFeed();
  });
  for (const [selector, property] of [['#unread-button', 'unreadOnly'], ['#saved-button', 'savedOnly']]) {
    document.querySelector(selector).addEventListener('click', (event) => {
      state[property] = !state[property];
      event.currentTarget.classList.toggle('active', state[property]);
      event.currentTarget.setAttribute('aria-pressed', String(state[property]));
      state.visible = PAGE_SIZE;
      renderFeed();
    });
  }
  document.querySelector('#load-more').addEventListener('click', () => {
    state.visible += PAGE_SIZE;
    renderFeed();
  });
  document.querySelector('#exploit-all').addEventListener('click', () => {
    state.category = 'all';
    state.source = 'exploit-db';
    state.period = 30;
    state.visible = PAGE_SIZE;
    document.querySelector('#source-select').value = 'exploit-db';
    document.querySelector('#period-select').value = '30';
    for (const tab of document.querySelectorAll('#category-tabs button')) {
      tab.classList.toggle('active', tab.dataset.category === 'all');
      tab.setAttribute('aria-pressed', String(tab.dataset.category === 'all'));
    }
    renderFeed();
    document.querySelector('#feed').scrollIntoView({ behavior: 'smooth' });
  });
}

async function loadFeed() {
  try {
    const response = await fetch(`./data/feed.json?v=${Date.now()}`, { cache: 'no-store' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const feed = await response.json();
    if (feed.schemaVersion !== 1 || !Array.isArray(feed.items)) throw new Error('Invalid feed format');
    state.items = feed.items.filter((item) => item && item.id && item.title && safeUrl(item.url) && !Number.isNaN(new Date(item.publishedAt).getTime()));
    state.items.sort((a, b) => new Date(b.publishedAt) - new Date(a.publishedAt));
    state.sources = Array.isArray(feed.sources) ? feed.sources : [];
    state.checkedAt = feed.checkedAt;
    const sourceSelect = document.querySelector('#source-select');
    for (const source of state.sources) {
      const option = el('option', '', source.name);
      option.value = source.id;
      sourceSelect.append(option);
    }
    renderSummary();
    renderPriority();
    renderExploitWatch();
    renderSources();
    renderFeed();
  } catch (error) {
    document.querySelector('#feed-list').replaceChildren(el('div', 'empty-feed', 'フィードを読み込めませんでした。ページを再読み込みしてください。'));
    document.querySelector('#priority-grid').replaceChildren(el('div', 'empty-priority', '重要な更新を読み込めませんでした。'));
    document.querySelector('#exploit-list').replaceChildren(el('p', 'exploit-empty', 'Exploit Database の更新を読み込めませんでした。'));
    document.querySelector('#update-status').textContent = `読み込みエラー: ${error.message}`;
    document.querySelector('#hero-update').textContent = 'データを確認できません';
    document.querySelector('#result-count').textContent = '—';
  }
}

setupControls();
loadFeed();
