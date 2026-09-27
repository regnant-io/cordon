/* Cordon, desktop.

   Everything shown comes from one `snapshot` command, polled: faster while
   something moves (a model loading, a download, a seal), slower when idle.
   Values from the app, model names from a Hugging Face repository included,
   are only ever written with textContent. */

(() => {
'use strict';

const $ = (id) => document.getElementById(id);
const qa = (sel, root = document) => [...root.querySelectorAll(sel)];

function el(tag, props, ...children) {
  const n = document.createElement(tag);
  if (typeof props === 'string') n.className = props;
  else if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else if (k === 'dataset') Object.assign(n.dataset, v);
      // Through the CSSOM: the app's CSP refuses style attributes.
      else if (k === 'style') n.style.cssText = v;
      else n.setAttribute(k, v === true ? '' : v);
    }
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}

function icon(name, cls = 'ico') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', cls);
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#${name}`);
  svg.append(use);
  return svg;
}

/* The mark is drawn inline rather than through <use>: its accent square has
   to take the page's CSS, which a <use> clone does not reliably do. */
function mark() {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('class', 'brand-mark');
  svg.setAttribute('viewBox', '0 0 32 32');
  const path = document.createElementNS(ns, 'path');
  path.setAttribute('d', 'M4 22V4H28V28H11V11H21V21');
  path.setAttribute('fill', 'none');
  path.setAttribute('stroke', 'currentColor');
  path.setAttribute('stroke-width', '2.6');
  path.setAttribute('stroke-linecap', 'square');
  const core = document.createElementNS(ns, 'rect');
  core.setAttribute('class', 'mark-core');
  for (const [k, v] of [['x', '13.8'], ['y', '13.8'], ['width', '4.4'], ['height', '4.4']]) core.setAttribute(k, v);
  svg.append(path, core);
  return svg;
}

const btn = (label, cls, onclick, ico) =>
  el('button', { class: `btn ${cls || ''}`.trim(), type: 'button', onclick }, ico ? icon(ico) : null, label);

let invoke = null;
let win = null;
let snap = null;
let status = null;
let logMark = 0;
let logLines = [];
let view = null;
let draft = null;
let openConsoleWhenReady = true;
let pollTimer = null;
let showLog = false;
let selectedMode = null;

/* -- Formatting ----------------------------------------------------------- */

function bytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}
function duration(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, '0')}s`;
  const h = Math.floor(m / 60);
  return h < 48 ? `${h}h ${m % 60}m` : `${Math.floor(h / 24)}d ${h % 24}h`;
}
const date = (iso) => iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—';
const short = (hex, n = 16) => hex ? (hex.length > n ? `${hex.slice(0, n)}…` : hex) : '—';
const tidy = (line) => line.replace(/^\S+Z\s+/, '').replace(/^(INFO|DEBUG)\s+(llama:\s+)?/, '');

let toastTimer = null;
function toast(message, tone) {
  const t = $('toast');
  t.textContent = message;
  t.dataset.tone = tone || '';
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, tone === 'bad' ? 6000 : 3200);
}

async function call(command, args) {
  try {
    return await invoke(command, args);
  } catch (e) {
    toast(String(e), 'bad');
    throw e;
  }
}
const quiet = (p) => p.catch(() => {});

/* -- Dialog --------------------------------------------------------------- */

/* A modal with optional fields. Resolves with the field values, or null. */
function ask({ title, text, fields = [], confirm = 'Continue', danger = false, extra }) {
  const dlg = $('dialog');
  const form = $('dialog-form');
  const inputs = {};
  const body = el('div', 'dlg-body', el('h2', { text: title }), text ? el('p', { text }) : null);
  for (const f of fields) {
    const id = `f-${f.name}`;
    let control;
    if (f.type === 'select') {
      control = el('select', { class: 'input', id });
      for (const o of f.options) control.append(el('option', { value: o.value, text: o.label }));
      control.value = f.value ?? f.options[0]?.value;
    } else if (f.type === 'segmented') {
      control = el('div', { class: 'segmented', role: 'group' });
      let current = f.value ?? f.options[0].value;
      for (const o of f.options) {
        const b = el('button', { type: 'button', text: o.label, 'aria-pressed': String(o.value === current) });
        b.onclick = () => { current = o.value; qa('button', control).forEach((x) => x.setAttribute('aria-pressed', String(x === b))); };
        control.append(b);
      }
      control.value = () => current;
    } else {
      control = el('input', { class: `input ${f.mono ? 'input--mono' : ''}`, id, value: f.value ?? '', placeholder: f.placeholder ?? '', spellcheck: 'false', autocomplete: 'off' });
    }
    inputs[f.name] = control;
    body.append(el('div', 'field', el('label', { for: id, text: f.label }), control, f.help ? el('div', { class: 'help', text: f.help }) : null));
  }
  if (extra) body.append(extra);
  const cancel = el('button', { class: 'btn btn--ghost', type: 'button', text: 'Cancel' });
  const ok = el('button', { class: `btn ${danger ? 'btn--danger-solid' : 'btn--primary'}`, type: 'submit', text: confirm });
  form.replaceChildren(body, el('div', 'dlg-foot', cancel, ok));
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (done) return; done = true; dlg.close(); resolve(v); };
    cancel.onclick = () => finish(null);
    dlg.onclose = () => finish(null);
    form.onsubmit = (e) => {
      e.preventDefault();
      const values = {};
      for (const [k, c] of Object.entries(inputs)) values[k] = typeof c.value === 'function' ? c.value() : c.value;
      finish(values);
    };
    dlg.showModal();
    const first = Object.values(inputs).find((c) => c.tagName === 'INPUT');
    (first || ok).focus();
  });
}

/* -- Polling -------------------------------------------------------------- */

const phase = () => snap?.phase.phase;
const running = () => phase() === 'running';
const busyPhase = () => ['starting', 'stopping'].includes(phase());
const downloading = () => ['resolving', 'downloading', 'verifying'].includes(snap?.download?.stage);
const jobRunning = () => snap?.job?.stage === 'running';
const consoleUp = () => running() && !!snap.phase.console;
const hardened = () => snap && snap.settings.mode !== 'light';

async function refresh() {
  clearTimeout(pollTimer);
  try {
    const next = await invoke('snapshot', { logAfter: logMark });
    logMark = next.log_mark;
    if (next.logs.length) logLines = logLines.concat(next.logs).slice(-400);
    snap = next;
    if (running() && !snap.phase.console) status = await invoke('node_status').catch(() => null);
    else status = null;
    render();
  } catch (e) {
    toast(`Cannot reach the app: ${e}`, 'bad');
  }
  const fast = busyPhase() || downloading() || jobRunning();
  pollTimer = setTimeout(refresh, fast ? 400 : 1500);
}

/* -- Routing -------------------------------------------------------------- */

const PAGES = ['home', 'models', 'bundles', 'keys', 'deployment', 'remote', 'settings'];

function route() {
  const hash = location.hash.slice(1);
  if (PAGES.includes(hash)) return hash;
  if (!snap.settings.model && !snap.bundles.length && !busyPhase()) return 'welcome';
  return 'home';
}

function show(name) {
  for (const s of qa('#main > section')) s.hidden = s.id !== `view-${name}`;
  if (view !== name) $('main').scrollTop = 0;
  view = name;
  $('app').toggleAttribute('data-bare', name === 'welcome' || name === 'outside');
  for (const item of qa('.nav-item[data-go]')) {
    item.setAttribute('aria-current', item.dataset.go === name ? 'page' : 'false');
  }
}

function go(page) {
  if (page === 'settings') draft = null;
  if (page === 'home' && consoleUp()) { openConsole('overview'); return; }
  history.replaceState(null, '', page ? `#${page}` : location.pathname);
  render();
}

async function openConsole(v) {
  openConsoleWhenReady = false;
  await call('open_console', { view: v || null });
}

/* -- Render --------------------------------------------------------------- */

function render() {
  if (!snap) return;
  applyTheme(snap.settings.theme);
  $('app').dataset.platform = snap.platform === 'macos' ? 'macos' : snap.platform;
  const target = route();

  // A node that has just come up in Light mode opens straight into its console.
  if (target === 'home' && consoleUp() && openConsoleWhenReady && !location.hash) {
    openConsole('overview');
    return;
  }
  if (busyPhase()) openConsoleWhenReady = true;
  show(target);

  renderChrome();
  if (view === 'welcome') renderWelcome();
  if (view === 'home') renderHome();
  if (view === 'models') renderModels();
  if (view === 'bundles') renderBundles();
  if (view === 'keys') renderKeys();
  if (view === 'deployment') renderDeployment();
  if (view === 'remote') renderRemote();
  if (view === 'settings') renderSettings();
}

let appliedTheme = null;
function applyTheme(theme) {
  if (theme === appliedTheme) return;
  appliedTheme = theme;
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
  quiet(win?.setTheme(theme === 'light' || theme === 'dark' ? theme : null) ?? Promise.resolve());
}

function modelName() {
  const key = snap.settings.model;
  if (!key) return '';
  if (key.startsWith('bundle:')) {
    const b = snap.bundles.find((x) => `bundle:${x.id}` === key);
    return b ? b.model_name : key.slice(7);
  }
  const found = snap.models.find((m) => m.key === key);
  return found?.name ?? key.split(/[\\/]/).pop();
}

function modeName(id) {
  return snap.modes.find((m) => m.id === id)?.name ?? id;
}

function nodeLine() {
  const p = snap.phase;
  if (p.phase === 'running') return { tone: 'ok', text: `Running · ${p.model}` };
  if (p.phase === 'starting') return { tone: 'busy', text: `Starting · ${p.step}` };
  if (p.phase === 'stopping') return { tone: 'busy', text: 'Stopping' };
  if (p.phase === 'failed') return { tone: 'bad', text: 'Could not start' };
  if (downloading()) return { tone: 'busy', text: 'Downloading a model' };
  return { tone: '', text: snap.settings.model ? 'Stopped' : 'No model yet' };
}

function renderChrome() {
  const line = nodeLine();
  $('tb-dot').dataset.tone = line.tone;
  $('tb-text').textContent = line.text + (hardened() ? ` · ${modeName(snap.settings.mode)} mode` : '');

  const primary = $('tb-primary');
  primary.hidden = false;
  primary.replaceChildren();
  if (running()) {
    primary.append(icon('i-stop', 'ico ico--sm'), 'Stop');
    primary.onclick = stopNode;
  } else if (busyPhase()) {
    primary.append('Cancel');
    primary.onclick = stopNode;
  } else if (snap.settings.model) {
    primary.append(icon('i-play', 'ico ico--sm'), 'Start');
    primary.onclick = startNode;
  } else {
    primary.hidden = true;
  }

  // Console pages exist only while a Light-mode node serves its console.
  for (const item of qa('.nav-item[data-console]')) {
    item.setAttribute('aria-disabled', String(!consoleUp()));
    item.title = consoleUp() ? '' : hardened()
      ? 'The console is not served outside Light mode.'
      : 'Available while Cordon is running.';
  }
  $('n-models').textContent = snap.models.length || '';
  $('n-bundles').textContent = snap.bundles.length || '';
  $('n-keys').hidden = snap.key.present || !(hardened() || snap.bundles.length);
  $('n-mode').textContent = modeName(snap.settings.mode);
  $('n-remote').textContent = snap.settings.remote.enabled ? 'On' : '';
}

async function startNode() {
  openConsoleWhenReady = true;
  history.replaceState(null, '', location.pathname);
  await call('start');
  refresh();
}
async function stopNode() {
  openConsoleWhenReady = false;
  await call('stop');
  refresh();
}

/* -- Model rows ----------------------------------------------------------- */

function progressFor(dl) {
  const wrap = el('div', { style: 'margin-top:8px' });
  const bar = el('div', dl.total ? 'progress' : 'progress progress--busy');
  const fill = el('div', 'progress-fill');
  if (dl.total) fill.style.width = `${Math.min(100, (dl.downloaded / dl.total) * 100).toFixed(1)}%`;
  bar.append(fill);
  let text;
  if (dl.stage === 'resolving') text = 'Finding the file…';
  else if (dl.stage === 'verifying') text = 'Checking the digest…';
  else {
    text = `${bytes(dl.downloaded)}${dl.total ? ` of ${bytes(dl.total)}` : ''}`;
    if (dl.bytes_per_second) text += ` · ${bytes(dl.bytes_per_second)}/s`;
  }
  wrap.append(bar, el('div', { class: 'row-meta', text }));
  return wrap;
}

function catalogRows() {
  const dl = snap.download;
  const busy = downloading();
  const rows = [];
  if (dl && (busy || dl.stage === 'failed') && !snap.catalog.some((c) => c.reference === dl.reference)) {
    const body = el('div', 'grow', el('div', { class: 'row-title', text: dl.reference }));
    if (busy) body.append(progressFor(dl));
    else body.append(el('div', { class: 'row-desc', style: 'color:var(--bad)', text: dl.error }));
    rows.push(el('div', 'row', el('div', 'row-icon', icon('i-download')), body,
      busy ? el('div', 'row-control', btn('Cancel', 'btn--sm', () => call('cancel_download').then(refresh))) : null));
  }
  for (const entry of snap.catalog) {
    const mine = dl && dl.reference === entry.reference;
    const title = el('div', 'row-title', entry.name);
    if (entry.recommended) title.append(el('span', { class: 'badge', dataset: { tone: 'accent' }, text: 'Recommended' }));
    const body = el('div', 'grow', title,
      el('div', { class: 'row-desc', text: entry.summary }),
      el('div', 'row-meta', el('span', { text: bytes(entry.size_bytes) }), el('span', { text: `${entry.memory_gib} GB memory` }), el('span', { text: entry.license })));
    const control = el('div', 'row-control');
    if (mine && busy) {
      body.append(progressFor(dl));
      control.append(btn('Cancel', 'btn--sm', () => call('cancel_download').then(refresh)));
    } else if (entry.on_disk) {
      const inUse = snap.settings.model === entry.local_id;
      const use = btn(inUse ? 'In use' : 'Use', 'btn--sm', () => selectModel(entry.local_id));
      use.disabled = inUse && phase() !== 'failed';
      control.append(use);
    } else {
      const get = btn('Download', entry.recommended ? 'btn--sm btn--primary' : 'btn--sm', () => startDownload(entry.reference));
      get.disabled = busy || !snap.downloads_allowed;
      control.append(get);
    }
    if (mine && dl.stage === 'failed') body.append(el('div', { class: 'row-desc', style: 'color:var(--bad)', text: dl.error }));
    rows.push(el('div', 'row', el('div', 'row-icon', icon('i-cube')), body, control));
  }
  return rows;
}

function hardwareSummary() {
  const rt = snap.runtime;
  const gpus = rt.devices.map((d) => d.free_mib ? `${d.name}, ${(d.free_mib / 1024).toFixed(1)} GB free` : d.name);
  return `${gpus.length ? gpus.join(' · ') : 'No GPU found; models run on the CPU'} · ${rt.cpu_threads} CPU threads`;
}

async function startDownload(reference) {
  openConsoleWhenReady = true;
  await call('download', { reference });
  refresh();
}
async function selectModel(key) {
  openConsoleWhenReady = true;
  history.replaceState(null, '', location.pathname);
  await call('select_model', { key });
  refresh();
}
async function importModel() {
  openConsoleWhenReady = true;
  const picked = await call('import_model');
  if (picked) history.replaceState(null, '', location.pathname);
  refresh();
}

/* -- Welcome -------------------------------------------------------------- */

function renderWelcome() {
  $('welcome-catalog').replaceChildren(...catalogRows());
  $('hardware-line').textContent = hardwareSummary();
}

/* -- Home ----------------------------------------------------------------- */

function renderHome() {
  const host = $('home');
  const p = snap.phase;
  const nodes = [];

  if (p.phase === 'running' && !p.console) {
    nodes.push(...statusPage(p));
  } else if (p.phase === 'running') {
    nodes.push(el('div', 'hero',
      el('div', 'hero-mark', icon('i-check')),
      el('h1', { text: 'Cordon is running' }),
      el('p', { class: 'lede', text: `${p.model}, served at ${p.api}` }),
      el('div', 'actions', btn('Open console', 'btn--primary btn--lg', () => openConsole('overview'), 'i-arrow'))));
  } else if (p.phase === 'starting' || p.phase === 'stopping') {
    const boot = el('div', 'boot',
      el('div', 'progress progress--busy', el('div', 'progress-fill')),
      el('div', 'boot-step', el('span', { text: p.phase === 'starting' ? p.step : 'Releasing the runtime' }),
        el('span', { class: 'num', text: p.elapsed_ms != null ? duration(p.elapsed_ms) : '' })));
    const log = el('pre', { class: 'log', style: 'margin-top:16px' });
    log.hidden = !showLog;
    fillLog(log);
    boot.append(log, el('div', { class: 'actions', style: 'margin-top:16px' },
      btn(showLog ? 'Hide details' : 'Show details', 'btn--ghost btn--sm', () => { showLog = !showLog; render(); }),
      el('span', 'spacer'),
      btn('Cancel', 'btn--sm', stopNode)));
    nodes.push(el('div', 'hero',
      el('div', 'hero-mark', el('span', { class: 'dot', dataset: { tone: 'busy' } })),
      el('h1', { text: p.phase === 'starting' ? 'Starting Cordon' : 'Stopping' }),
      el('p', { class: 'lede', text: modelName() })), boot);
  } else {
    const failed = p.phase === 'failed';
    const hero = el('div', 'hero',
      el('div', 'hero-mark', failed ? icon('i-alert') : mark()),
      el('h1', { text: failed ? 'Cordon could not start' : 'Cordon is stopped' }),
      el('p', { class: 'lede', text: snap.settings.model ? `${modelName()}${hardened() ? ` · ${modeName(snap.settings.mode)} mode` : ''}` : 'Choose a model to begin.' }));
    const actions = el('div', 'actions');
    if (snap.settings.model) actions.append(btn(failed ? 'Try again' : 'Start', 'btn--primary btn--lg', startNode, 'i-play'));
    actions.append(btn('Models', 'btn--lg', () => go('models')));
    hero.append(actions);
    nodes.push(hero);
    if (!snap.runtime.binary) {
      nodes.push(notice('bad', 'llama.cpp is missing from this installation.', 'Reinstall Cordon, or set CORDON_LLAMA_SERVER to a llama-server binary.'));
    }
    if (failed) {
      const n = notice('bad', 'What went wrong', null);
      n.querySelector('.body').append(el('pre', { text: p.error }));
      nodes.push(n);
      const log = el('pre', { class: 'log', style: 'margin-top:12px;height:280px' });
      fillLog(log);
      nodes.push(log, el('div', { class: 'actions', style: 'margin-top:12px' },
        btn('Show log file', 'btn--ghost btn--sm', () => call('reveal', { what: 'logs' }))));
    }
  }
  host.replaceChildren(...nodes);
  const log = host.querySelector('.log');
  if (log) log.scrollTop = log.scrollHeight;
}

function fillLog(box) {
  box.textContent = logLines.slice(-200).map(tidy).join('\n');
}

function notice(tone, title, text, ico) {
  return el('div', { class: 'notice', dataset: { tone } },
    icon(ico || (tone === 'bad' || tone === 'warn' ? 'i-alert' : 'i-info')),
    el('div', 'body', title ? el('strong', { text: title }) : null, title && text ? ' ' : null, text));
}

/* A hardened node serves no console; this is its status page. */
function statusPage(p) {
  const s = status;
  const out = [el('div', 'page-head',
    el('div', 'text', el('h1', { text: 'Overview' }),
      el('p', { class: 'lede', text: `${modeName(snap.settings.mode)} mode. The operator console is not served outside Light mode; this page reads the node directly.` })))];
  if (!s) { out.push(el('div', 'empty', 'Reading the node…')); return out; }
  const tone = s.status === 'healthy' ? 'ok' : s.status === 'quarantined' ? 'bad' : 'warn';
  out.push(el('div', 'stats',
    stat('State', el('span', { style: 'display:flex;align-items:center;gap:10px' }, el('span', { class: 'dot', dataset: { tone } }), s.status), `Up ${duration(s.uptime_seconds * 1000)}`),
    stat('In flight', `${s.active_requests} / ${s.max_concurrent}`, `p50 ${s.latency_ms_p50} ms · p99 ${s.latency_ms_p99} ms`),
    stat('Audit entries', s.audit_entries.toLocaleString(), 'hash-chained and signed'),
    stat('Integrity', s.tamper_detected ? 'Tampered' : s.integrity_ok == null ? 'Pending' : s.integrity_ok ? 'Verified' : 'Failed', s.integrity_checked_at ? `checked ${new Date(s.integrity_checked_at).toLocaleTimeString()}` : 'first check pending')));
  out.push(el('div', 'section', el('div', 'section-head', el('h2', { text: 'Node' })),
    el('div', 'group', el('div', 'row row--top', facts([
      ['API', p.api, true],
      ['Model', `${p.model}${s.bundle ? ' (sealed)' : ''}`],
      ['Client identity', p.mtls ? 'Client certificates, TLS 1.3' : 'Header, loopback only'],
      ['Signing key', { cmk_derived: 'Derived from your Client Master Key', local: "This computer's key", ephemeral: 'Generated at start' }[s.key_provenance] ?? s.key_provenance],
      ['Measurements', `${s.measurement_source}${s.measurements_pinned ? ', pinned' : ', not pinned'}`],
      ['Audit chain head', s.chain_head || '—', true],
      ['Log verifying key', s.log_verifying_key, true],
      ['Node ID', s.node_id, true],
    ])))));
  out.push(el('div', 'section', notice('', 'Verify this node from anywhere.',
    'Clients check attestation at /v1/attestation, and anyone with the log verifying key can check the audit log offline with `cordon verify-log`.')));
  return out;
}

function stat(k, v, s) {
  return el('div', 'stat', el('div', { class: 'k', text: k }), el('div', 'v', v), el('div', { class: 's', text: s }));
}

function facts(pairs) {
  const dl = el('dl', 'facts grow');
  for (const [k, v, mono] of pairs) dl.append(el('dt', { text: k }), el('dd', { class: mono ? 'mono' : null, text: v }));
  return dl;
}

/* -- Models --------------------------------------------------------------- */

let armed = null;
function armedButton(id, label, confirmLabel, action) {
  const b = btn(armed === id ? confirmLabel : label, `btn--sm ${armed === id ? 'btn--danger' : 'btn--ghost'}`, async () => {
    if (armed !== id) {
      armed = id;
      setTimeout(() => { if (armed === id) { armed = null; render(); } }, 3000);
      render();
      return;
    }
    armed = null;
    await action();
    refresh();
  });
  return b;
}

function renderModels() {
  $('models-egress').hidden = snap.downloads_allowed;
  $('models-catalog-section').hidden = !snap.downloads_allowed;
  const rows = snap.models.map((m) => {
    const selected = m.key === snap.settings.model;
    const title = el('div', 'row-title', m.name);
    if (selected) title.append(el('span', { class: 'badge', dataset: { tone: running() ? 'ok' : 'accent' }, text: running() ? 'Serving' : 'Selected' }));
    if (m.imported) title.append(el('span', { class: 'badge', text: 'Opened from disk' }));
    else if (!m.digest_verified) title.append(el('span', { class: 'badge', dataset: { tone: 'warn' }, text: 'Digest unverified' }));
    const meta = el('div', 'row-meta', el('span', { text: bytes(m.size_bytes) }), m.quant ? el('span', { text: m.quant }) : null, m.source ? el('span', { text: m.source }) : null);
    const control = el('div', 'row-control');
    if (!selected) {
      const use = btn('Use', 'btn--sm', () => selectModel(m.key));
      use.disabled = hardened();
      if (hardened()) use.title = 'This mode serves only sealed bundles.';
      control.append(use);
    }
    control.append(btn('Seal…', 'btn--sm btn--ghost', () => sealModel(m.key, m.name)),
      armedButton(`m:${m.key}`, m.imported ? 'Forget' : 'Delete', 'Confirm', async () => {
        await call('remove_model', { key: m.key });
        toast(m.imported ? 'Forgotten. The file is untouched.' : 'Model deleted');
      }));
    const row = el('div', 'row', el('div', 'row-icon', icon('i-cube')),
      el('div', 'grow', title, meta, el('div', { class: 'row-meta mono selectable', text: m.path })), control);
    if (selected) row.dataset.selected = '';
    return row;
  });
  if (!rows.length) rows.push(el('div', 'empty', 'No models yet. Download one below, or open a GGUF file.'));
  $('models-local').replaceChildren(...rows);
  $('models-count').textContent = snap.models.length === 1 ? '1 model' : `${snap.models.length} models`;
  $('models-catalog').replaceChildren(...catalogRows());
}

/* -- Bundles -------------------------------------------------------------- */

function jobCard() {
  const j = snap.job;
  if (!j) return null;
  const pct = j.total ? Math.min(100, (j.done / j.total) * 100) : 0;
  const tone = { running: 'accent', done: 'ok', failed: 'bad', cancelled: '' }[j.stage];
  const n = el('div', { class: 'notice', dataset: { tone }, style: 'margin-bottom:16px' },
    icon(j.stage === 'done' ? 'i-check' : j.stage === 'failed' ? 'i-alert' : 'i-lock'));
  const body = el('div', 'body', el('strong', { text: j.label }));
  if (j.stage === 'running') {
    const bar = el('div', j.total ? 'progress' : 'progress progress--busy', el('div', 'progress-fill'));
    if (j.total) bar.firstChild.style.width = `${pct.toFixed(1)}%`;
    body.append(el('div', { style: 'margin:8px 0 4px' }, bar),
      el('div', { class: 'faint num', text: j.total ? `${bytes(j.done)} of ${bytes(j.total)} · ${pct.toFixed(0)}%` : 'Preparing…' }));
  } else if (j.stage === 'done') {
    body.append(el('div', { text: j.result + (j.output ? ` · ${j.output}` : '') }));
  } else if (j.stage === 'failed') {
    body.append(el('pre', { text: j.error }));
  } else {
    body.append(el('div', { text: 'Cancelled. Nothing was left behind.' }));
  }
  n.append(body, j.stage === 'running'
    ? btn('Cancel', 'btn--sm', () => call('bundle_cancel'))
    : btn('Dismiss', 'btn--sm btn--ghost', () => call('bundle_dismiss').then(refresh)));
  return n;
}

async function sealModel(sourceKey, name) {
  if (!snap.key.present) {
    toast('Create or import a Client Master Key first.');
    go('keys');
    return;
  }
  const sources = snap.models.map((m) => ({ value: m.key, label: m.name }));
  sources.push({ value: '', label: 'Choose a file…' });
  const v = await ask({
    title: 'Seal a model',
    text: `Encrypts the weights under your key (${snap.key.id}) for the principal "${snap.settings.principal}". The original file is left as it is.`,
    fields: [
      { name: 'source', label: 'Model', type: 'select', options: sources, value: sourceKey ?? sources[0].value },
      { name: 'name', label: 'Name', value: name ?? '', placeholder: 'Taken from the file if empty' },
      { name: 'version', label: 'Version', value: '1.0.0' },
      { name: 'to', label: 'Save to', type: 'segmented', value: 'store', options: [{ value: 'store', label: 'This computer' }, { value: 'folder', label: 'A folder, for another node' }] },
    ],
    confirm: 'Seal',
  });
  if (!v) return;
  const chosen = snap.models.find((m) => m.key === v.source);
  const started = await call('bundle_seal', {
    source: v.source || null,
    name: v.name.trim() || chosen?.name || '',
    version: v.version,
    toFolder: v.to === 'folder',
  });
  if (started) { go('bundles'); refresh(); }
}

function renderBundles() {
  const keyHost = $('bundles-key-notice');
  keyHost.replaceChildren();
  if (!snap.key.present) {
    const n = notice('warn', 'No key yet.', 'Sealing and serving bundles needs your Client Master Key.');
    n.append(btn('Create key', 'btn--sm', () => keyCreate()));
    n.style.marginBottom = '16px';
    keyHost.append(n);
  }
  $('bundles-job').replaceChildren(...[jobCard()].filter(Boolean));

  const rows = snap.bundles.map((b) => {
    const key = `bundle:${b.id}`;
    const selected = snap.settings.model === key;
    const title = el('div', 'row-title', b.model_name || b.id);
    if (b.model_version) title.append(el('span', { class: 'faint', style: 'font-weight:400', text: `v${b.model_version}` }));
    if (selected) title.append(el('span', { class: 'badge', dataset: { tone: running() ? 'ok' : 'accent' }, text: running() ? 'Serving' : 'Selected' }));
    if (b.problem) title.append(el('span', { class: 'badge', dataset: { tone: 'bad' }, text: 'Refused' }));
    const meta = el('div', 'row-meta',
      el('span', { text: bytes(b.size_bytes) }),
      el('span', { text: `${b.shards} shard${b.shards === 1 ? '' : 's'}` }),
      el('span', { text: `for ${b.principal}` }),
      el('span', { text: `sealed ${date(b.created_at)}` }));
    const body = el('div', 'grow', title, meta, el('div', { class: 'row-meta mono selectable', text: b.id }));
    if (b.problem) body.append(el('div', { class: 'row-desc', style: 'color:var(--bad)', text: b.problem }));
    const control = el('div', 'row-control');
    if (!b.problem) {
      if (!selected) control.append(btn('Serve', 'btn--sm', () => selectModel(key)));
      control.append(
        btn('Verify', 'btn--sm btn--ghost', () => call('bundle_verify', { id: b.id }).then(refresh)),
        btn('Export…', 'btn--sm btn--ghost', () => call('bundle_export', { id: b.id }).then(refresh)));
    }
    control.append(armedButton(`b:${b.id}`, 'Delete', 'Confirm', async () => {
      await call('bundle_remove', { id: b.id });
      toast('Bundle deleted');
    }));
    const row = el('div', 'row', el('div', { class: 'row-icon', dataset: { tone: 'accent' } }, icon('i-lock')), body, control);
    if (selected) row.dataset.selected = '';
    return row;
  });
  if (!rows.length) {
    rows.push(el('div', 'empty',
      el('h3', { text: 'No sealed bundles' }),
      el('div', { text: 'Seal a model you have, or import a bundle sealed on another machine.' }),
      el('div', 'actions', btn('Seal a model', 'btn--primary', () => sealModel()), btn('Import…', '', bundleImport))));
  }
  $('bundles-list').replaceChildren(...rows);
}

async function bundleImport() {
  if (await call('bundle_import')) refresh();
}

/* -- Keys ----------------------------------------------------------------- */

async function keyCreate() {
  await call('key_create');
  toast('Key created. Back it up: bundles sealed under it cannot be opened without it.');
  refresh();
}

function renderKeys() {
  const k = snap.key;
  const out = [];
  if (k.present) {
    out.push(el('div', 'group',
      el('div', 'row',
        el('div', 'row-icon', icon('i-key')),
        el('div', 'grow', el('div', 'row-title', 'Client Master Key', el('span', { class: 'badge', dataset: { tone: 'ok' }, text: 'Present' })),
          el('div', 'row-meta', el('span', { class: 'mono', text: k.id }), el('span', { text: `created ${date(k.created)}` }), el('span', { text: `principal ${snap.settings.principal}` }))),
        el('div', 'row-control',
          btn('Back up…', 'btn--sm', async () => {
            const to = await call('key_backup');
            if (to) toast(`Saved to ${to}. Keep it offline.`);
          }, 'i-download')))));
    out.push(el('div', 'section', notice('', 'Kept on this computer only.',
      'It is readable only by your account, and never shown. The app uses it to seal bundles and, when a node needs it, to start one. Losing it makes every bundle sealed under it unreadable, so keep a backup somewhere offline.')));
    out.push(el('div', 'section',
      el('div', 'section-head', el('h2', { text: 'From the command line' })),
      el('div', 'code selectable', `cordon bundle seal --weights model.gguf --cmk-file "${snap.paths.key_dir}${snap.platform === 'windows' ? '\\' : '/'}cmk.hex"`)));
    out.push(el('div', 'section',
      el('div', 'section-head', el('h2', { text: 'Danger zone' })),
      el('div', 'group', el('div', 'row',
        el('div', 'grow', el('div', 'row-title', 'Remove this key'),
          el('div', 'row-desc', 'Bundles sealed under it stay on disk but cannot be served until the key is imported again.')),
        el('div', 'row-control', btn('Remove…', 'btn--sm btn--danger', async () => {
          const ok = await ask({ title: 'Remove the key?', text: `Without key ${k.id}, its bundles cannot be decrypted. Make sure you have a backup.`, confirm: 'Remove key', danger: true });
          if (!ok) return;
          await call('key_remove');
          toast('Key removed');
          refresh();
        }))))));
  } else {
    out.push(el('div', 'group', el('div', 'empty',
      el('h3', { text: 'No key yet' }),
      el('div', { text: 'Create one here, or import one made with `cordon keys generate` or on another machine.' }),
      el('div', 'actions',
        btn('Create key', 'btn--primary', keyCreate),
        btn('Import…', '', async () => { if (await call('key_import')) { toast('Key imported'); refresh(); } })))));
  }
  $('keys-body').replaceChildren(...out);
}

/* -- Deployment ----------------------------------------------------------- */

const CHECK_ICON = { met: 'i-check', todo: 'i-dash', blocked: 'i-x' };

function renderDeployment() {
  const current = snap.settings.mode;
  if (!selectedMode) selectedMode = current;
  const cards = snap.modes.map((m) => {
    const r = snap.readiness.find((x) => x.mode === m.id);
    const tag = m.id === current
      ? el('span', { class: 'badge', dataset: { tone: 'accent' }, text: 'Current' })
      : r.ready ? el('span', { class: 'badge', dataset: { tone: 'ok' }, text: 'Ready' })
      : r.checks.some((c) => c.state === 'blocked') ? el('span', { class: 'badge', text: 'Needs hardware' })
      : el('span', { class: 'badge', dataset: { tone: 'warn' }, text: `${r.checks.filter((c) => c.state !== 'met').length} to do` });
    const card = el('button', { class: 'mode', type: 'button', 'aria-pressed': String(m.id === selectedMode), onclick: () => { selectedMode = m.id; render(); } },
      el('div', 'top', el('span', { class: 'name', text: m.name }), el('span', 'spacer'), tag),
      el('div', { class: 'sum', text: m.summary }));
    return card;
  });
  $('modes').replaceChildren(...cards);

  const r = snap.readiness.find((x) => x.mode === selectedMode);
  const info = snap.modes.find((m) => m.id === selectedMode);
  const host = $('readiness');
  const out = [];
  if (!r.checks.length) {
    out.push(el('div', 'section-head', el('h2', { text: `${info.name} mode` })),
      notice('', null, 'No requirements. Signatures come from a key kept on this computer, client identity is a header on loopback, and the operator console is available. Suited to development and evaluation, not to data a third party must trust.'));
  } else {
    out.push(el('div', 'section-head', el('h2', { text: `What ${info.name} mode needs` }),
      el('p', { text: `${r.checks.filter((c) => c.state === 'met').length} of ${r.checks.length} in place` })));
    out.push(el('div', 'group checks', ...r.checks.map(checkRow)));
    if (!r.ready && r.checks.some((c) => c.state === 'blocked')) {
      out.push(el('div', { style: 'margin-top:12px' }, notice('warn', 'Not possible on this machine.',
        'The node would refuse to start rather than claim a guarantee it cannot back. Configure this mode here to carry the settings over, or run Cordon on hardware that provides it.')));
    }
  }
  const actions = el('div', { class: 'actions', style: 'margin-top:20px' });
  if (selectedMode === current) {
    actions.append(el('span', { class: 'faint', text: `Cordon runs in ${info.name} mode.` }));
  } else {
    const sw = btn(`Switch to ${info.name}`, 'btn--primary', () => switchMode(selectedMode));
    sw.disabled = !r.ready;
    actions.append(sw, !r.ready ? el('span', { class: 'faint', text: 'Complete the steps above first.' }) : null);
  }
  out.push(actions);
  host.replaceChildren(...out);
}

function checkRow(c) {
  const control = el('div', 'row-control');
  const hw = snap.settings.hardware;
  if (c.id === 'key' && c.state !== 'met') control.append(btn('Create key', 'btn--sm', keyCreate), btn('Import…', 'btn--sm btn--ghost', () => call('key_import').then(refresh)));
  if (c.id === 'bundle' && c.state !== 'met') control.append(btn('Sealed bundles', 'btn--sm', () => go('bundles')));
  if (c.id === 'root') {
    const options = [];
    if (snap.hardware.tpm) options.push(['tpm2', 'TPM 2.0']);
    if (snap.hardware.sev_snp) options.push(['sev_snp', 'SEV-SNP']);
    if (options.length) {
      const seg = el('div', { class: 'segmented', role: 'group' });
      for (const [id, label] of options) {
        seg.append(el('button', { type: 'button', text: label, 'aria-pressed': String(hw.source === id), onclick: () => editSettings((s) => { s.hardware.source = id; s.hardware.pcrs = {}; s.hardware.measurement = null; }) }));
      }
      control.append(seg);
    }
    if (hw.source === 'tpm2') control.append(btn('Attestation key…', 'btn--sm btn--ghost', () => call('hardware_pick', { what: 'ak' }).then(refresh)));
    if (hw.source === 'sev_snp') control.append(btn('AMD root…', 'btn--sm btn--ghost', () => call('hardware_pick', { what: 'amd_root' }).then(refresh)));
    control.append(btn('Check again', 'btn--sm btn--ghost', async () => { await call('hardware_probe'); refresh(); }, 'i-refresh'));
  }
  if (c.id === 'pins' && c.state !== 'blocked') {
    control.append(btn(c.state === 'met' ? 'Record again' : 'Record', 'btn--sm', async () => {
      await call('hardware_capture');
      toast('Measurements recorded');
      refresh();
    }));
  }
  if (c.id === 'fips') {
    const box = el('input', { type: 'checkbox' });
    box.checked = hw.fips_level_4;
    box.onchange = () => editSettings((s) => { s.hardware.fips_level_4 = box.checked; });
    control.append(el('label', 'switch', el('span', { class: 'faint', text: 'I confirm' }), box, el('span', 'switch-track')));
  }
  return el('div', 'row',
    el('span', { class: 'check-icon', dataset: { state: c.state } }, icon(CHECK_ICON[c.state])),
    el('div', 'grow', el('div', { class: 'row-title', text: c.title }), el('div', { class: 'row-desc', text: c.detail })),
    control);
}

async function editSettings(fn, restart = false) {
  const next = structuredClone(snap.settings);
  fn(next);
  await call('save_settings', { settings: next, restart });
  refresh();
}

async function switchMode(id) {
  const info = snap.modes.find((m) => m.id === id);
  const ok = await ask({
    title: `Switch to ${info.name} mode?`,
    text: id === 'light'
      ? 'The node signs with this computer\'s local key again, and serves the operator console. Its audit log for the other mode is kept.'
      : `The node restarts in ${info.name} mode with its own audit log, signed with your key. The operator console is not served in this mode; the Overview page takes its place.`,
    confirm: 'Switch',
  });
  if (!ok) return;
  openConsoleWhenReady = id === 'light';
  await editSettings((s) => { s.mode = id; }, running() || busyPhase());
  toast(`${info.name} mode`);
}

/* -- Remote access -------------------------------------------------------- */

function renderRemote() {
  const r = snap.remote;
  const s = snap.settings.remote;
  const out = [];

  const toggle = el('input', { type: 'checkbox' });
  toggle.checked = s.enabled;
  toggle.onchange = async () => {
    if (toggle.checked) {
      const ok = await ask({
        title: 'Allow connections from other machines?',
        text: `The API will listen on port ${s.port} on every network this computer is on. Only callers holding a certificate you issue here get past the TLS handshake.`,
        confirm: 'Allow',
      });
      if (!ok) { toggle.checked = false; return; }
    }
    await editSettings((x) => { x.remote.enabled = toggle.checked; }, running() || busyPhase());
    toast(toggle.checked ? 'Remote access on' : 'Remote access off');
  };
  const port = el('input', { class: 'input input--num', type: 'number', min: '1', max: '65535', value: String(s.port) });
  port.onchange = () => editSettings((x) => { x.remote.port = parseInt(port.value, 10) || x.remote.port; }, s.enabled && running());
  const names = el('input', { class: 'input input--mono', value: s.names.join(', '), placeholder: 'cordon.example.com, 203.0.113.7', spellcheck: 'false' });
  names.onchange = () => editSettings((x) => { x.remote.names = names.value.split(',').map((n) => n.trim()).filter(Boolean); }, s.enabled && running());

  out.push(el('div', 'group',
    el('div', 'setting',
      el('div', null, el('div', { class: 'label', text: 'Allow remote connections' }),
        el('div', { class: 'help', text: s.enabled ? 'On. The API accepts certificate-holding clients from the network.' : 'Off. The node is reachable from this computer only.' })),
      el('div', 'control', el('label', 'switch', toggle, el('span', 'switch-track')))),
    el('div', 'setting',
      el('div', null, el('div', { class: 'label', text: 'Port' }), el('div', { class: 'help', text: 'Forward this port on your router or firewall to reach it from the internet. Cordon does not open ports for you.' })),
      el('div', 'control', port)),
    el('div', 'setting',
      el('div', null, el('div', { class: 'label', text: 'Public names' }), el('div', { class: 'help', text: 'Host names or addresses clients use from outside, such as a DNS name. The server certificate covers them.' })),
      el('div', 'control', names))));

  const posture = [
    ['TLS 1.3 only', 'No older protocol versions, no plaintext listener while this is on.'],
    ['A certificate for every caller', 'The handshake fails without one from this app\'s CA, before any request is read.'],
    ['Pinned and revocable', 'Each certificate is pinned by fingerprint. Revoking removes it; unknown clients are denied.'],
    ['Rate-limited and bounded', 'Per-client request limits, a 10 s handshake deadline and a cap on open connections.'],
    ['The console stays local', 'The operator console listens on 127.0.0.1 only, whatever this page says.'],
  ];
  out.push(el('div', 'section', el('div', 'section-head', el('h2', { text: 'How it is protected' })),
    el('div', 'group checks', ...posture.map(([t, d]) => el('div', 'row',
      el('span', { class: 'check-icon', dataset: { state: 'met' } }, icon('i-check')),
      el('div', 'grow', el('div', { class: 'row-title', text: t }), el('div', { class: 'row-desc', text: d })))))));

  const clients = r.clients.map((c) => {
    const now = Date.now();
    const expired = new Date(c.not_after).getTime() < now;
    const state = c.revoked_at ? ['bad', 'Revoked'] : expired ? ['warn', 'Expired'] : ['ok', 'Active'];
    const control = el('div', 'row-control');
    if (!c.revoked_at) control.append(armedButton(`c:${c.fingerprint}`, 'Revoke', 'Confirm revoke', async () => {
      const restarted = await call('remote_revoke', { fingerprint: c.fingerprint });
      toast(restarted ? `${c.id} revoked. The node is restarting to apply it.` : `${c.id} revoked`);
    }));
    return el('div', 'row', el('div', 'row-icon', icon('i-terminal')),
      el('div', 'grow', el('div', 'row-title', c.id, el('span', { class: 'badge', dataset: { tone: state[0] }, text: state[1] })),
        el('div', 'row-meta', el('span', { text: `issued ${date(c.issued_at)}` }), el('span', { text: c.revoked_at ? `revoked ${date(c.revoked_at)}` : `valid until ${date(c.not_after)}` }), el('span', { class: 'mono', text: short(c.fingerprint) }))),
      control);
  });
  if (!clients.length) clients.push(el('div', 'empty', 'No certificates issued yet. Issue one for each machine or service that should call this node.'));
  out.push(el('div', 'section',
    el('div', 'section-head', el('h2', { text: 'Clients' }), el('p', { text: 'One certificate per machine or service.' }),
      el('div', 'actions', r.clients.some((c) => c.revoked_at) ? btn('Clear revoked', 'btn--sm btn--ghost', () => call('remote_clear_revoked').then(refresh)) : null,
        btn('Issue certificate', 'btn--sm btn--primary', issueClient, 'i-plus'))),
    el('div', 'group', ...clients)));

  const facts_ = [['Addresses', r.addresses.join('\n') || '—']];
  if (r.certificate_names.length) facts_.push(['Certificate covers', r.certificate_names.join(', ')]);
  if (r.certificate_expires) facts_.push(['Certificate expires', `${date(r.certificate_expires)} (renewed automatically)`]);
  if (r.certificate_fingerprint) facts_.push(['Server fingerprint', r.certificate_fingerprint, true]);
  out.push(el('div', 'section', el('div', 'section-head', el('h2', { text: 'Server' })),
    el('div', 'group', el('div', 'row row--top', facts(facts_)))));
  $('remote-body').replaceChildren(...out);
}

async function issueClient() {
  const v = await ask({
    title: 'Issue a client certificate',
    text: 'You choose a folder next; the client\'s certificate, private key and the CA are saved there, with a README. The private key is not kept here.',
    fields: [
      { name: 'name', label: 'Client name', placeholder: 'build-server', help: 'Letters, digits, - _ . @. The node sees this as the client ID.' },
      { name: 'days', label: 'Valid for', type: 'segmented', value: '90', options: [{ value: '30', label: '30 days' }, { value: '90', label: '90 days' }, { value: '365', label: '1 year' }] },
    ],
    confirm: 'Choose folder…',
  });
  if (!v || !v.name.trim()) return;
  const saved = await call('remote_issue', { name: v.name.trim(), days: parseInt(v.days, 10) });
  if (saved) toast(`Saved to ${saved}`);
  refresh();
}

/* -- Settings ------------------------------------------------------------- */

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function gpuMode(v) { return v === 'auto' || v === 'all' ? v : v === '0' ? 'cpu' : 'custom'; }
function setIfIdle(input, value) { if (document.activeElement !== input && input.value !== value) input.value = value; }

function renderSettings() {
  if (!draft) draft = structuredClone(snap.settings);
  const saved = snap.settings;

  const mode = gpuMode(draft.gpu_layers);
  for (const b of qa('#gpu-mode button')) b.setAttribute('aria-pressed', String(b.dataset.mode === mode));
  $('gpu-custom').hidden = mode !== 'custom';
  if (mode === 'custom') setIfIdle($('gpu-layers'), draft.gpu_layers);
  $('devices').textContent = snap.runtime.devices.length
    ? snap.runtime.devices.map((d) => `${d.name}${d.free_mib ? `, ${(d.free_mib / 1024).toFixed(1)} GB free` : ''}`).join(' · ')
    : 'No GPU found. Models run on the CPU.';

  if (![...$('ctx').options].some((o) => o.value === String(draft.context_size))) {
    $('ctx').append(el('option', { value: String(draft.context_size), text: `${draft.context_size.toLocaleString()} tokens` }));
  }
  setIfIdle($('ctx'), String(draft.context_size));
  setIfIdle($('parallel'), String(draft.parallel));
  $('threads-auto').checked = draft.threads == null;
  $('threads').hidden = draft.threads == null;
  $('threads-hint').textContent = draft.threads == null ? 'Automatic' : `of ${snap.runtime.cpu_threads}`;
  if (draft.threads != null) setIfIdle($('threads'), String(draft.threads));

  setIfIdle($('api-port'), String(draft.api_port));
  setIfIdle($('console-port'), String(draft.console_port));
  setIfIdle($('principal'), draft.principal);
  $('autostart').checked = draft.start_on_launch;
  $('api-url').textContent = running() ? snap.phase.api : '';
  for (const b of qa('#theme button')) b.setAttribute('aria-pressed', String(b.dataset.theme === saved.theme));

  const cli = snap.cli;
  const cliRows = [];
  if (cli.path) {
    const toggle = el('input', { type: 'checkbox' });
    toggle.checked = cli.on_path;
    toggle.disabled = !cli.can_install;
    toggle.onchange = async () => {
      try { await call('cli_install', { install: toggle.checked }); } finally { refresh(); }
    };
    cliRows.push(el('div', 'setting',
      el('div', null, el('div', { class: 'label', text: 'Add cordon to PATH' }),
        el('div', { class: 'help', text: cli.hint || 'The same tools as a server install: cordon bundle, cordon keys, cordon pki, cordon verify-log and the rest.' })),
      el('div', 'control', el('label', 'switch', toggle, el('span', 'switch-track')))),
      el('div', 'row', el('div', { class: 'grow mono selectable faint', style: 'font-size:12px', text: cli.path }),
        el('div', 'row-control', btn('Show', 'btn--sm btn--ghost', () => call('reveal', { what: 'cli' })))));
  } else {
    cliRows.push(el('div', 'row', el('div', { class: 'grow faint', text: cli.hint || 'Not included in this build.' })));
  }
  $('cli').replaceChildren(...cliRows);

  const rt = snap.runtime;
  $('about').replaceChildren(...[
    ['Cordon', `${snap.version} (${snap.platform})`],
    ['llama.cpp', rt.binary ? `${rt.version ?? 'unknown version'}${rt.bundled ? ', bundled' : ', from PATH'}` : 'not found'],
    ['Data folder', snap.paths.data_dir],
    ['Log file', snap.paths.log_file],
  ].flatMap(([k, v]) => [el('dt', { text: k }), el('dd', { class: k.includes('folder') || k.includes('file') ? 'mono selectable' : null, text: v })]));

  const changed = !same(draft, saved);
  const restartable = running() || busyPhase();
  const needsRestart = restartable && !same({ ...draft, start_on_launch: null, theme: null }, { ...saved, start_on_launch: null, theme: null });
  $('savebar').hidden = !changed;
  $('save').textContent = needsRestart ? 'Save and restart' : 'Save';
  $('settings-lede').textContent = running()
    ? 'Changes to performance or ports restart the node. Requests in flight finish first.'
    : 'Settings apply the next time the node starts.';
}

function edit(fn) { fn(draft); render(); }
const int = (v, f) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : f; };

$('gpu-mode').addEventListener('click', (e) => {
  const m = e.target.closest('button')?.dataset.mode;
  if (!m) return;
  edit((d) => { d.gpu_layers = m === 'auto' ? 'auto' : m === 'all' ? 'all' : m === 'cpu' ? '0' : (gpuMode(d.gpu_layers) === 'custom' ? d.gpu_layers : '20'); });
});
$('gpu-layers').addEventListener('input', (e) => edit((d) => { d.gpu_layers = String(Math.max(1, int(e.target.value, 1))); }));
$('ctx').addEventListener('change', (e) => edit((d) => { d.context_size = int(e.target.value, 8192); }));
$('parallel').addEventListener('input', (e) => edit((d) => { d.parallel = int(e.target.value, d.parallel); }));
$('threads-auto').addEventListener('change', (e) => edit((d) => { d.threads = e.target.checked ? null : Math.max(1, Math.floor(snap.runtime.cpu_threads / 2)); }));
$('threads').addEventListener('input', (e) => edit((d) => { d.threads = int(e.target.value, d.threads); }));
$('api-port').addEventListener('input', (e) => edit((d) => { d.api_port = int(e.target.value, d.api_port); }));
$('console-port').addEventListener('input', (e) => edit((d) => { d.console_port = int(e.target.value, d.console_port); }));
$('principal').addEventListener('input', (e) => edit((d) => { d.principal = e.target.value.trim(); }));
$('autostart').addEventListener('change', (e) => edit((d) => { d.start_on_launch = e.target.checked; }));
$('theme').addEventListener('click', async (e) => {
  const t = e.target.closest('button')?.dataset.theme;
  if (!t || t === snap.settings.theme) return;
  // Appearance applies at once, without touching other unsaved edits.
  const next = structuredClone(snap.settings);
  next.theme = t;
  if (draft) draft.theme = t;
  await call('save_settings', { settings: next, restart: false });
  refresh();
});
$('discard').onclick = () => { draft = null; render(); };
$('save').onclick = async () => {
  const restart = (running() || busyPhase()) && !same({ ...draft, start_on_launch: null, theme: null }, { ...snap.settings, start_on_launch: null, theme: null });
  await call('save_settings', { settings: draft, restart });
  draft = null;
  if (restart) { openConsoleWhenReady = true; history.replaceState(null, '', location.pathname); }
  toast(restart ? 'Saved. Restarting the node.' : 'Saved');
  refresh();
};

/* -- Wiring --------------------------------------------------------------- */

document.addEventListener('click', (e) => {
  const t = e.target.closest('[data-go], [data-console], [data-act], [data-reveal]');
  if (!t || t.getAttribute('aria-disabled') === 'true') return;
  if (t.dataset.go) go(t.dataset.go);
  else if (t.dataset.console) openConsole(t.dataset.console);
  else if (t.dataset.reveal) call('reveal', { what: t.dataset.reveal });
  else if (t.dataset.act === 'import-model') importModel();
  else if (t.dataset.act === 'bundle-seal') sealModel();
  else if (t.dataset.act === 'bundle-import') bundleImport();
  else if (t.dataset.act === 'repo-download') {
    const input = t.parentElement.querySelector('[data-repo]');
    const ref = input.value.trim();
    if (!ref) { input.focus(); return; }
    startDownload(ref);
  }
});
document.addEventListener('keydown', (e) => {
  if (e.target.matches?.('[data-repo]') && e.key === 'Enter') e.target.parentElement.querySelector('[data-act="repo-download"]').click();
});

addEventListener('keydown', (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && e.key === ',') { e.preventDefault(); go('settings'); }
  if (e.key === 'F5' || (mod && e.key.toLowerCase() === 'r')) e.preventDefault();
});
addEventListener('contextmenu', (e) => {
  const editable = e.target instanceof Element && e.target.closest('input, textarea, .selectable, pre');
  if (!editable) e.preventDefault();
});
addEventListener('hashchange', render);

/* -- Window --------------------------------------------------------------- */

function wireWindow() {
  win = window.__TAURI__?.window?.getCurrentWindow?.();
  if (!win) { $('wc').hidden = true; return; }
  $('wc-min').onclick = () => quiet(win.minimize());
  $('wc-max').onclick = () => quiet(win.toggleMaximize());
  $('wc-close').onclick = () => quiet(win.close());
  const sync = async () => {
    const max = await win.isMaximized().catch(() => false);
    $('wc-max').querySelector('use').setAttribute('href', max ? '#w-restore' : '#w-max');
    $('wc-max').setAttribute('aria-label', max ? 'Restore' : 'Maximise');
  };
  let t = null;
  addEventListener('resize', () => { clearTimeout(t); t = setTimeout(sync, 120); });
  sync();
}

/* -- Boot ----------------------------------------------------------------- */

function boot() {
  invoke = window.__TAURI__.core.invoke;
  wireWindow();
  // Coming back from the console to an app page should not bounce straight
  // back to the console.
  if (location.hash && location.hash !== '#home') openConsoleWhenReady = false;
  refresh();
}

if (window.__TAURI__?.core) boot();
else {
  let tries = 0;
  const wait = setInterval(() => {
    if (window.__TAURI__?.core) { clearInterval(wait); boot(); }
    else if (++tries > 20) { clearInterval(wait); show('outside'); }
  }, 100);
}
})();
