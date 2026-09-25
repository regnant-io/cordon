/* Cordon launcher.

   Everything shown here comes from one `snapshot` command, polled: faster
   while something is moving (a model loading, a download), slower when idle.
   Values from the app, model names from a Hugging Face repository included,
   are only ever written with textContent. */

(() => {
'use strict';

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

let invoke = null;
let snap = null;
let logMark = 0;
let logLines = [];
let view = null;
let draft = null;
let openConsoleWhenReady = true;
let pollTimer = null;
let removeArmed = null;

/* -- Formatting ---------------------------------------------------------- */

function bytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function elapsed(ms) {
  const s = Math.floor(ms / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}

/* Log lines arrive as `2026-09-25T11:30:00.04Z  INFO message`. The time is
   noise on a progress screen. llama.cpp's own output comes through at debug
   level under `llama:`, which is the level it is read at here, so that prefix
   goes too; warnings and errors keep theirs. */
function tidy(line) {
  return line.replace(/^\S+Z\s+/, '').replace(/^(INFO|DEBUG)\s+(llama:\s+)?/, '');
}

let toastTimer = null;
function toast(message) {
  const t = $('toast');
  t.textContent = message;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 3600);
}

async function call(command, args) {
  try {
    return await invoke(command, args);
  } catch (e) {
    toast(String(e));
    throw e;
  }
}

/* -- Polling ------------------------------------------------------------- */

async function refresh() {
  clearTimeout(pollTimer);
  try {
    const next = await invoke('snapshot', { logAfter: logMark });
    logMark = next.log_mark;
    if (next.logs.length) {
      logLines = logLines.concat(next.logs).slice(-400);
    }
    snap = next;
    render();
  } catch (e) {
    toast(`Cannot reach the app: ${e}`);
  }
  const busy = snap && (['starting', 'stopping'].includes(snap.phase.phase) || downloading());
  pollTimer = setTimeout(refresh, busy ? 400 : 1500);
}

const downloading = () =>
  ['resolving', 'downloading', 'verifying'].includes(snap?.download?.stage);

/* -- Routing ------------------------------------------------------------- */

function route() {
  const hash = location.hash.slice(1);
  const phase = snap.phase.phase;

  if (hash === 'settings' || hash === 'catalog') return hash;
  if (phase === 'starting' || phase === 'stopping') return 'starting';
  if (phase === 'running') return 'running';
  if (phase === 'failed') return 'stopped';
  return snap.settings.model ? 'stopped' : 'welcome';
}

function show(name) {
  for (const section of document.querySelectorAll('main > section')) {
    section.hidden = section.id !== `view-${name}`;
  }
  if (view !== name) $('main').scrollTop = 0;
  view = name;
}

function go(hash) {
  if (hash === 'settings') draft = null;
  history.replaceState(null, '', hash ? `#${hash}` : location.pathname);
  render();
}

async function openConsole() {
  openConsoleWhenReady = false;
  await call('open_console');
}

/* -- Render -------------------------------------------------------------- */

function render() {
  if (!snap) return;
  const target = route();

  if (target === 'running') {
    // Arriving at a running node from startup: go straight to the console.
    if (openConsoleWhenReady) { openConsole(); return; }
    show('stopped');
  } else {
    if (target === 'starting') openConsoleWhenReady = true;
    show(target);
  }

  renderBar();
  if (view === 'welcome') renderCatalog($('catalog'));
  if (view === 'catalog') renderCatalog($('catalog-2'));
  if (view === 'starting') renderStarting();
  if (view === 'stopped') renderStopped();
  if (view === 'settings') renderSettings();
}

function modelName() {
  const key = snap.settings.model;
  const found = snap.models.find((m) => m.key === key);
  return found?.name ?? (key ? key.split(/[\\/]/).pop() : '');
}

function renderBar() {
  const phase = snap.phase;
  const chip = $('status-chip');
  let text = 'Stopped', tone = '';
  if (phase.phase === 'running') { text = `Running · ${modelName()}`; tone = 'ok'; }
  else if (phase.phase === 'starting') { text = 'Starting'; tone = 'warn'; }
  else if (phase.phase === 'stopping') { text = 'Stopping'; tone = 'warn'; }
  else if (phase.phase === 'failed') { text = 'Failed to start'; tone = 'stop'; }
  else if (downloading()) { text = 'Downloading'; tone = 'warn'; }
  chip.textContent = text;
  chip.dataset.tone = tone;

  $('bar-console').hidden = phase.phase !== 'running' || view === 'starting';
  $('bar-settings').hidden = view === 'settings' || view === 'starting' || !snap.settings.model;
}

/* -- Catalog ------------------------------------------------------------- */

function renderCatalog(host) {
  const dl = snap.download;
  const busy = downloading();
  const rows = [];

  for (const entry of snap.catalog) {
    const item = el('div', 'item');
    const body = el('div');
    const name = el('div', 'item-name', entry.name);
    if (entry.recommended) name.appendChild(el('span', 'tag', 'Recommended'));
    if (entry.on_disk) name.appendChild(el('span', 'tag tag--plain', 'Downloaded'));
    body.appendChild(name);
    body.appendChild(el('div', 'item-desc', entry.summary));
    const meta = el('div', 'item-meta');
    meta.appendChild(el('span', null, bytes(entry.size_bytes)));
    meta.appendChild(el('span', null, `About ${entry.memory_gib} GB of memory`));
    meta.appendChild(el('span', null, entry.license));
    body.appendChild(meta);

    const side = el('div', 'actions');
    const mine = dl && dl.reference === entry.reference;
    if (mine && busy) {
      body.appendChild(progressFor(dl));
      const cancel = el('button', 'btn btn--sm', 'Cancel');
      cancel.onclick = () => call('cancel_download').then(refresh);
      side.appendChild(cancel);
    } else if (entry.on_disk) {
      const use = el('button', 'btn btn--sm', snap.settings.model === entry.local_id ? 'In use' : 'Use');
      use.disabled = snap.settings.model === entry.local_id && snap.phase.phase !== 'failed';
      use.onclick = () => selectModel(entry.local_id);
      side.appendChild(use);
    } else {
      const get = el('button', entry.recommended ? 'btn btn--sm btn--primary' : 'btn btn--sm', 'Download');
      get.disabled = busy;
      get.onclick = () => startDownload(entry.reference);
      side.appendChild(get);
    }
    if (mine && dl.stage === 'failed') body.appendChild(el('div', 'item-desc error', dl.error));

    item.append(body, side);
    rows.push(item);
  }

  // A download started from the repository field has no catalog row.
  if (dl && busy && !snap.catalog.some((c) => c.reference === dl.reference)) {
    const item = el('div', 'item');
    const body = el('div');
    body.appendChild(el('div', 'item-name', dl.reference));
    body.appendChild(progressFor(dl));
    const cancel = el('button', 'btn btn--sm', 'Cancel');
    cancel.onclick = () => call('cancel_download').then(refresh);
    item.append(body, cancel);
    rows.unshift(item);
  } else if (dl && dl.stage === 'failed' && !snap.catalog.some((c) => c.reference === dl.reference)) {
    const item = el('div', 'item');
    const body = el('div');
    body.appendChild(el('div', 'item-name', dl.reference));
    body.appendChild(el('div', 'item-desc error', dl.error));
    item.append(body, el('span'));
    rows.unshift(item);
  }

  host.replaceChildren(...rows);

  const line = $('hardware-line');
  if (host.id === 'catalog') {
    line.hidden = false;
    line.classList.add('section-gap');
    line.textContent = hardwareSummary();
  }
  $('repo-go').disabled = busy;
}

function progressFor(dl) {
  const wrap = el('div');
  const bar = el('div', dl.total ? 'progress' : 'progress progress--busy');
  const fill = el('div', 'progress-fill');
  if (dl.total) fill.style.width = `${Math.min(100, (dl.downloaded / dl.total) * 100).toFixed(1)}%`;
  bar.appendChild(fill);
  wrap.appendChild(bar);
  let text;
  if (dl.stage === 'resolving') text = 'Finding the file…';
  else if (dl.stage === 'verifying') text = 'Checking the digest…';
  else {
    text = `${bytes(dl.downloaded)}${dl.total ? ` of ${bytes(dl.total)}` : ''}`;
    if (dl.bytes_per_second) text += ` · ${bytes(dl.bytes_per_second)}/s`;
  }
  wrap.appendChild(el('div', 'item-meta', text));
  return wrap;
}

function hardwareSummary() {
  const rt = snap.runtime;
  const gpus = rt.devices.map((d) =>
    d.free_mib ? `${d.name} (${(d.free_mib / 1024).toFixed(1)} GB free)` : d.name);
  const parts = [gpus.length ? gpus.join(', ') : 'No GPU found, so models run on the CPU'];
  parts.push(`${rt.cpu_threads} CPU threads`);
  return `This computer: ${parts.join(' · ')}`;
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

$('repo-go').onclick = () => {
  const reference = $('repo').value.trim();
  if (!reference) { $('repo').focus(); return; }
  startDownload(reference);
};
$('repo').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('repo-go').click(); });

async function importModel() {
  openConsoleWhenReady = true;
  const picked = await call('import_model');
  if (picked) history.replaceState(null, '', location.pathname);
  refresh();
}
$('import').onclick = importModel;
$('settings-import').onclick = importModel;

/* -- Starting ------------------------------------------------------------ */

function renderStarting() {
  const phase = snap.phase;
  const name = modelName();
  $('boot-title').textContent = phase.phase === 'stopping' ? 'Stopping' : 'Starting Cordon';
  $('boot-model').textContent = name;
  $('boot-step').textContent = phase.phase === 'starting' ? phase.step : 'Releasing the runtime';
  $('boot-elapsed').textContent = phase.elapsed_ms != null ? elapsed(phase.elapsed_ms) : '';
  fillLog($('boot-log'));
}

function fillLog(box) {
  if (box.hidden) return;
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 24;
  box.textContent = logLines.slice(-200).map(tidy).join('\n');
  if (atBottom) box.scrollTop = box.scrollHeight;
}

$('boot-details').onclick = () => {
  const box = $('boot-log');
  box.hidden = !box.hidden;
  $('boot-details').textContent = box.hidden ? 'Show details' : 'Hide details';
  $('boot-details').setAttribute('aria-expanded', String(!box.hidden));
  fillLog(box);
  box.scrollTop = box.scrollHeight;
};
$('boot-cancel').onclick = () => { openConsoleWhenReady = false; call('stop').then(refresh); };

/* -- Stopped or failed --------------------------------------------------- */

function renderStopped() {
  const phase = snap.phase;
  const failed = phase.phase === 'failed';
  const running = phase.phase === 'running';
  $('stopped-title').textContent = running ? 'Cordon is running' : failed ? 'Cordon could not start' : 'Cordon is stopped';
  $('stopped-model').textContent = modelName();
  $('stopped-error').hidden = !failed;
  $('stopped-error').textContent = failed ? phase.error : '';
  $('stopped-log').hidden = !failed;
  if (failed) fillLog($('stopped-log'));
  $('stopped-start').textContent = running ? 'Open console' : failed ? 'Try again' : 'Start';
  if (!snap.runtime.binary) {
    $('stopped-error').hidden = false;
    $('stopped-error').textContent = 'llama.cpp is missing from this installation. Reinstall Cordon, or set CORDON_LLAMA_SERVER to a llama-server binary.';
  }
}

$('stopped-start').onclick = () => {
  if (snap.phase.phase === 'running') { openConsole(); return; }
  openConsoleWhenReady = true;
  call('start').then(refresh);
};
$('stopped-settings').onclick = () => go('settings');
$('stopped-logs').onclick = () => call('reveal', { what: 'logs' });

/* -- Settings ------------------------------------------------------------ */

const saved = () => snap.settings;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function gpuMode(value) {
  if (value === 'auto' || value === 'all') return value;
  if (value === '0') return 'cpu';
  return 'custom';
}

function renderSettings() {
  if (!draft) draft = structuredClone(saved());
  const running = snap.phase.phase === 'running';

  // Models
  const host = $('models');
  const rows = snap.models.map((m) => {
    const item = el('div', 'item');
    const selected = m.key === saved().model;
    if (selected) item.dataset.selected = '';
    const body = el('div');
    const name = el('div', 'item-name', m.name);
    if (selected) name.appendChild(el('span', 'tag', running ? 'Running' : 'Selected'));
    if (m.imported) name.appendChild(el('span', 'tag tag--plain', 'Opened from disk'));
    else if (!m.digest_verified) name.appendChild(el('span', 'tag tag--warn', 'Digest unverified'));
    body.appendChild(name);
    const meta = el('div', 'item-meta');
    meta.appendChild(el('span', null, bytes(m.size_bytes)));
    if (m.quant) meta.appendChild(el('span', null, m.quant));
    if (m.source) meta.appendChild(el('span', null, m.source));
    body.appendChild(meta);
    body.appendChild(el('div', 'path', m.path));

    const side = el('div', 'actions');
    if (!selected) {
      const use = el('button', 'btn btn--sm', 'Use');
      use.onclick = () => selectModel(m.key);
      side.appendChild(use);
    }
    const remove = el('button', 'btn btn--sm btn--ghost',
      removeArmed === m.key ? (m.imported ? 'Confirm' : 'Confirm delete') : (m.imported ? 'Forget' : 'Delete'));
    if (removeArmed === m.key) remove.classList.add('btn--danger');
    remove.onclick = async () => {
      if (removeArmed !== m.key) {
        removeArmed = m.key;
        setTimeout(() => { if (removeArmed === m.key) { removeArmed = null; render(); } }, 3000);
        render();
        return;
      }
      removeArmed = null;
      await call('remove_model', { key: m.key });
      toast(m.imported ? 'Forgotten. The file is untouched.' : 'Model deleted');
      refresh();
    };
    side.appendChild(remove);
    item.append(body, side);
    return item;
  });
  if (!rows.length) {
    const item = el('div', 'item');
    item.append(el('div', 'item-desc', 'No models yet.'), el('span'));
    rows.push(item);
  }
  host.replaceChildren(...rows);
  $('models-count').textContent = snap.models.length === 1 ? '1 on this computer' : `${snap.models.length} on this computer`;

  // Performance
  const mode = gpuMode(draft.gpu_layers);
  for (const b of $('gpu-mode').querySelectorAll('button')) b.setAttribute('aria-pressed', String(b.dataset.mode === mode));
  $('gpu-custom').hidden = mode !== 'custom';
  if (mode === 'custom' && document.activeElement !== $('gpu-layers')) $('gpu-layers').value = draft.gpu_layers;
  $('devices').textContent = snap.runtime.devices.length
    ? snap.runtime.devices.map((d) => `${d.id}: ${d.name}${d.free_mib ? `, ${(d.free_mib / 1024).toFixed(1)} GB free` : ''}`).join(' · ')
    : 'No GPU was found. The model runs on the CPU whatever this is set to.';

  setIfIdle($('ctx'), String(draft.context_size));
  if (![...$('ctx').options].some((o) => o.value === String(draft.context_size))) {
    $('ctx').appendChild(el('option', null, `${draft.context_size.toLocaleString()} tokens`)).value = String(draft.context_size);
    $('ctx').value = String(draft.context_size);
  }
  setIfIdle($('parallel'), String(draft.parallel));
  $('threads-auto').checked = draft.threads == null;
  $('threads-custom').hidden = draft.threads == null;
  if (draft.threads != null) setIfIdle($('threads'), String(draft.threads));
  $('threads-hint').textContent = `of ${snap.runtime.cpu_threads}`;

  // Access
  setIfIdle($('api-port'), String(draft.api_port));
  setIfIdle($('console-port'), String(draft.console_port));
  $('autostart').checked = draft.start_on_launch;
  $('api-url').textContent = running ? `Serving at ${snap.phase.api}` : '';
  $('console-url').textContent = running
    ? `Serving at ${snap.phase.console.replace('?shell=desktop', '').replace('#overview', '')}` : '';

  // About
  const rt = snap.runtime;
  const facts = [
    ['Cordon', `${snap.version} (${snap.platform})`],
    ['llama.cpp', rt.binary ? `${rt.version ?? 'unknown version'}${rt.bundled ? ', bundled' : ', from PATH'}` : 'not found'],
    ['Runtime', rt.binary ?? '—'],
    ['Data folder', snap.paths.data_dir],
    ['Log file', snap.paths.log_file],
  ];
  $('about').replaceChildren(...facts.flatMap(([k, v]) => {
    const dd = el('dd', k === 'Runtime' || k.includes('folder') || k.includes('file') ? 'path' : null, v);
    return [el('dt', null, k), dd];
  }));

  // Save bar
  const changed = !same(draft, saved());
  $('save').disabled = !changed;
  $('discard').disabled = !changed;
  $('save').textContent = changed && ['running', 'starting'].includes(snap.phase.phase) ? 'Save and restart' : 'Save';
  $('save-note').textContent = changed ? 'Unsaved changes' : 'No unsaved changes';
  $('settings-lede').textContent = running
    ? 'Changes to the model or performance restart the runtime. Requests in flight finish first.'
    : 'Settings apply the next time the model starts.';
}

/* Do not overwrite a field while someone is typing in it. */
function setIfIdle(input, value) {
  if (document.activeElement !== input && input.value !== value) input.value = value;
}

function edit(fn) { fn(draft); render(); }
const int = (v, fallback) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : fallback; };

$('gpu-mode').addEventListener('click', (e) => {
  const mode = e.target.closest('button')?.dataset.mode;
  if (!mode) return;
  edit((d) => {
    d.gpu_layers = mode === 'auto' ? 'auto' : mode === 'all' ? 'all' : mode === 'cpu' ? '0'
      : (gpuMode(d.gpu_layers) === 'custom' ? d.gpu_layers : '20');
  });
});
$('gpu-layers').addEventListener('input', (e) => edit((d) => { d.gpu_layers = String(Math.max(1, int(e.target.value, 1))); }));
$('ctx').addEventListener('change', (e) => edit((d) => { d.context_size = int(e.target.value, 8192); }));
$('parallel').addEventListener('input', (e) => edit((d) => { d.parallel = int(e.target.value, d.parallel); }));
$('threads-auto').addEventListener('change', (e) => edit((d) => {
  d.threads = e.target.checked ? null : Math.max(1, Math.floor(snap.runtime.cpu_threads / 2));
}));
$('threads').addEventListener('input', (e) => edit((d) => { d.threads = int(e.target.value, d.threads); }));
$('api-port').addEventListener('input', (e) => edit((d) => { d.api_port = int(e.target.value, d.api_port); }));
$('console-port').addEventListener('input', (e) => edit((d) => { d.console_port = int(e.target.value, d.console_port); }));
$('autostart').addEventListener('change', (e) => edit((d) => { d.start_on_launch = e.target.checked; }));

$('discard').onclick = () => { draft = null; render(); };
$('save').onclick = async () => {
  const restart = ['running', 'starting'].includes(snap.phase.phase);
  const restartNeeded = restart && !same({ ...draft, start_on_launch: null }, { ...saved(), start_on_launch: null });
  await call('save_settings', { settings: draft, restart: restartNeeded });
  draft = null;
  if (restartNeeded) { openConsoleWhenReady = true; history.replaceState(null, '', location.pathname); }
  toast(restartNeeded ? 'Saved. Restarting the runtime.' : 'Saved');
  refresh();
};

$('settings-catalog').onclick = () => go('catalog');
$('catalog-back').onclick = () => go('settings');
$('show-data').onclick = () => call('reveal', { what: 'data' });
$('show-logs').onclick = () => call('reveal', { what: 'logs' });

$('bar-console').onclick = openConsole;
$('bar-settings').onclick = () => go('settings');

/* -- Application behaviour ----------------------------------------------- */

addEventListener('keydown', (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && e.key === ',') { e.preventDefault(); go('settings'); }
  if (e.key === 'Escape' && view === 'settings' && snap?.phase.phase === 'running') openConsole();
  if (e.key === 'F5' || (mod && e.key.toLowerCase() === 'r')) e.preventDefault();
});

addEventListener('contextmenu', (e) => {
  const editable = e.target instanceof Element && e.target.closest('input, textarea');
  if (!editable && !String(getSelection() ?? '')) e.preventDefault();
});

addEventListener('hashchange', render);

/* -- Boot ---------------------------------------------------------------- */

function boot() {
  invoke = window.__TAURI__.core.invoke;
  // Coming back from the console to its settings should not bounce straight
  // back to the console.
  if (location.hash === '#settings') openConsoleWhenReady = false;
  refresh();
}

if (window.__TAURI__?.core) boot();
else {
  // The API is injected before this script runs inside the app. Anywhere
  // else, the page has nothing to talk to.
  let tries = 0;
  const wait = setInterval(() => {
    if (window.__TAURI__?.core) { clearInterval(wait); boot(); }
    else if (++tries > 20) { clearInterval(wait); show('outside'); }
  }, 100);
}
})();
