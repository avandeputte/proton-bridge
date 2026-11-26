'use strict';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const $ = (id) => document.getElementById(id);

// h('div', {class: 'x', onclick: fn}, child, 'text', ...) builds DOM without
// ever interpreting data as HTML.
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, path, body) {
  const opts = { method, headers: { 'X-Mailbridge': '1' }, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, opts);
  } catch (e) {
    throw new HttpError(0, 'Cannot reach the container.');
  }
  let data = {};
  try { data = await res.json(); } catch (e) { /* empty body */ }
  if (!res.ok) throw new HttpError(res.status, data.error || ('Request failed (' + res.status + ')'));
  return data;
}

let toastTimer;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 4000);
}

// run an action from a button: disable it meanwhile, report failures.
async function act(button, fn, okMsg) {
  if (button) button.disabled = true;
  try {
    await fn();
    if (okMsg) toast(okMsg);
    await refresh();
  } catch (e) {
    if (e.status === 401) showSignIn(); else toast(e.message);
  } finally {
    if (button) button.disabled = false;
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    // clipboard API needs HTTPS; fall back for plain-HTTP setups.
    const ta = h('textarea', { class: 'offscreen' });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast('Copied');
}

function bytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + ' ' + units[i];
}

// ---------------------------------------------------------------------------
// views
// ---------------------------------------------------------------------------
let state = null;
let pollTimer = null;
const revealed = new Set();   // account ids whose bridge password is visible
let rendered = {};            // last rendered JSON per section, to avoid needless re-renders
let logsOpen = false;

function show(view) {
  for (const v of ['view-loading', 'view-signin', 'view-app']) $(v).hidden = v !== view;
  $('top-right').hidden = view !== 'view-app';
}

function showSignIn() {
  clearTimeout(pollTimer);
  state = null;
  rendered = {};
  revealed.clear();
  show('view-signin');
  $('signin-password').focus();
}

function changed(key, value) {
  const json = JSON.stringify(value);
  if (rendered[key] === json) return false;
  rendered[key] = json;
  return true;
}

async function refresh() {
  clearTimeout(pollTimer);
  try {
    state = await api('GET', 'api/state');
  } catch (e) {
    if (e.status === 401) { showSignIn(); return; }
    $('status-pill').textContent = 'unreachable';
    $('status-pill').className = 'pill err';
    pollTimer = setTimeout(refresh, 4000);
    return;
  }
  show('view-app');
  render();
  if (logsOpen) loadLogs();
  const busy = state.status !== 'running' || state.login.stage === 'working' || state.users.some((u) => u.syncing) ||
    Object.values(state.sync || {}).some((x) => x.state === 'syncing');
  pollTimer = setTimeout(refresh, busy ? 1500 : 4000);
}

function render() {
  const pill = $('status-pill');
  if (state.status !== 'running') {
    pill.textContent = 'bridge ' + state.status; pill.className = 'pill warn';
  } else if (!state.online) {
    pill.textContent = 'no connection to Proton'; pill.className = 'pill err';
  } else {
    pill.textContent = 'running'; pill.className = 'pill ok';
  }
  $('version').textContent = state.version ? 'Bridge ' + state.version : '';

  if (changed('notices', state.notices)) renderNotices();
  if (changed('accounts', [state.users, state.settings, state.connection, [...revealed], state.dovecot, syncView()])) renderAccounts();
  if (changed('login', [state.login, state.status])) renderLogin();
  if (changed('settings', [state.settings, state.status, state.dovecot])) renderSettings();
  if (changed('cert', state.dovecot)) {
    $('cert-note').textContent = state.dovecot
      ? 'In Dovecot mode, IMAP is encrypted with the same certificate as this page, and SMTP with bridge\'s own ' +
        'self-signed certificate, which you can download here. Mail clients will ask you to accept them.'
      : 'Bridge encrypts IMAP and SMTP with its own self-signed certificate. Mail clients will ask you to accept it; ' +
        'import the downloaded certificate if your client needs it installed first.';
  }
  if (changed('password', state.canChangePassword)) renderPassword();
}

function renderNotices() {
  const box = $('notices');
  box.replaceChildren();
  if (!state.notices.length) return;
  for (const n of state.notices.slice().reverse()) {
    box.append(h('div', { class: 'notice ' + n.level },
      h('span', { class: 'muted small' }, new Date(n.time).toLocaleString() + ' · '), n.message));
  }
  box.append(h('button', { class: 'link small', type: 'button',
    onclick: (e) => act(e.target, () => api('DELETE', 'api/notices')) }, 'Dismiss all'));
}

// What the page shows of the Dovecot sync, per login. Rendering from this
// instead of the raw status keeps the page still between routine syncs.
function syncView() {
  const out = {};
  for (const [login, x] of Object.entries(state.sync || {})) {
    const last = x.lastSync && !x.lastSync.startsWith('0001') ? new Date(x.lastSync) : null;
    out[login] = {
      state: x.state,
      message: x.message || '',
      messages: x.messages || 0,
      pending: x.pendingDeletions || 0,
      last: last ? last.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '',
    };
  }
  return out;
}

function syncBlock(login, showLogin) {
  const x = syncView()[login.toLowerCase()];
  const block = h('div', { class: 'sync' });
  if (showLogin) block.append(h('div', {}, h('code', {}, login)));
  if (!x) {
    block.append(h('span', { class: 'muted' }, 'Starting…'));
    return block;
  }

  const post = (path) => api('POST', path, { login });
  const button = (label, path, okMsg, confirmMsg, cls) => h('button', { class: 'mini' + (cls ? ' ' + cls : ''), type: 'button',
    onclick: (e) => {
      if (confirmMsg && !confirm(confirmMsg)) return;
      act(e.target, () => post(path), okMsg);
    } }, label);
  const rebuildMsg = 'Delete the Dovecot copy of ' + login + ' and download it again from Proton? ' +
    'Nothing is changed on Proton. Changes made in mail clients that were not synchronised yet are lost, ' +
    'and mail clients will download the mailbox again.';

  const pill = { ok: ['ok', 'in sync'], syncing: ['warn', 'synchronising'], waiting: ['warn', 'waiting'],
    paused: ['err', 'paused'], error: ['err', 'problem'] }[x.state] || ['warn', x.state];
  const summary = [x.messages + (x.messages === 1 ? ' message' : ' messages')];
  if (x.last) summary.push('last synchronised ' + x.last);
  block.append(h('div', { class: 'row' },
    h('span', { class: 'pill ' + pill[0] }, pill[1]),
    h('span', { class: 'muted small' }, summary.join(' · '))));

  if (x.message) block.append(h('div', { class: 'sync-msg small' + (x.state === 'error' ? ' error' : '') }, x.message));

  const actions = h('div', { class: 'row' });
  if (x.state === 'paused') {
    actions.append(
      button('Restore them from Proton', 'api/sync/rebuild', 'Downloading the mailbox again', rebuildMsg),
      button('Remove them from Proton too', 'api/sync/approve', 'Sync resumed',
        'Remove ' + x.pending + ' messages from Proton as well? Deleted mail cannot be brought back from here.', 'danger'));
  } else {
    actions.append(button('Sync now', 'api/sync/run', 'Sync started'));
    if (x.state !== 'waiting') actions.append(button('Rebuild from Proton', 'api/sync/rebuild', 'Downloading the mailbox again', rebuildMsg));
  }
  block.append(actions);
  return block;
}

function accountCard(u) {
  const s = state.settings;
  const c = state.connection;
  const pillClass = u.state === 'connected' ? 'ok' : (u.state === 'locked' ? 'warn' : 'err');
  const pillText = u.state === 'connected' ? (u.syncing ? 'synchronising' : 'connected')
    : (u.state === 'locked' ? 'starting' : 'signed out');

  const card = h('div', { class: 'card' },
    h('div', { class: 'row spread' },
      h('h3', {}, u.username),
      h('span', { class: 'pill ' + pillClass }, pillText)));

  if (u.totalBytes > 0) {
    card.append(h('div', { class: 'muted small' }, bytes(u.usedBytes) + ' of ' + bytes(u.totalBytes) + ' used'));
  }
  if (u.syncing) {
    card.append(h('progress', { max: '1', value: String(u.progress || 0) }),
      h('div', { class: 'muted small' }, 'First synchronisation: ' + Math.round((u.progress || 0) * 100) +
        '%. Mail clients can connect once this is complete.'));
  }

  if (u.state !== 'signedOut') {
    const shown = revealed.has(u.id);
    const logins = u.splitMode ? u.addresses : u.addresses.slice(0, 1);
    const copyBtn = (text) => h('button', { class: 'mini', type: 'button', onclick: () => copyText(text) }, 'Copy');

    card.append(h('div', { class: 'table-wrap' }, h('table', {},
      h('tr', {}, h('th', {}, 'IMAP server'),
        h('td', {}, h('code', {}, c.host), ' port ', h('code', {}, c.imapPort), ' · ',
          (state.dovecot ? false : s.imapSSL) ? 'SSL/TLS' : 'STARTTLS',
          (state.dovecot && c.imapsPort) ? [', or port ', h('code', {}, c.imapsPort), ' · SSL/TLS'] : null)),
      h('tr', {}, h('th', {}, 'SMTP server'),
        h('td', {}, h('code', {}, c.host), ' port ', h('code', {}, c.smtpPort), ' · ', s.smtpSSL ? 'SSL/TLS' : 'STARTTLS')),
      h('tr', {}, h('th', {}, u.splitMode ? 'Usernames' : 'Username'),
        h('td', {}, logins.map((a) => h('div', { class: 'row' }, h('code', {}, a), copyBtn(a))))),
      h('tr', {}, h('th', {}, 'Password'),
        h('td', {}, h('div', { class: 'row' },
          h('code', {}, shown ? u.password : '••••••••••••••••'),
          h('button', { class: 'mini', type: 'button', onclick: () => {
            if (shown) revealed.delete(u.id); else revealed.add(u.id);
            render();
          } }, shown ? 'Hide' : 'Show'),
          copyBtn(u.password)))),
      (!u.splitMode && u.addresses.length > 1) && h('tr', {}, h('th', {}, 'Also receives'),
        h('td', { class: 'muted' }, u.addresses.slice(1).join(', '))),
      (state.dovecot && u.state === 'connected') && h('tr', {}, h('th', {}, 'Dovecot copy'),
        h('td', {}, logins.map((a) => syncBlock(a, logins.length > 1)))))));

    card.append(h('p', { class: 'muted small' },
      'This password is generated by bridge for mail clients only. It is not your Proton password.'));
  } else {
    card.append(h('p', { class: 'muted' },
      'Signed out. Add the account again below to resume; its local mail cache is kept.'));
  }

  const actions = h('div', { class: 'row' });
  if (u.state !== 'signedOut') {
    if (u.addresses.length > 1) {
      actions.append(h('button', { type: 'button',
        onclick: (e) => {
          if (!confirm(u.splitMode
            ? 'Switch to combined mode? All addresses share one mailbox and one login. Mail clients need to be reconfigured.'
            : 'Switch to split mode? Each address gets its own mailbox and login. Mail clients need to be reconfigured.')) return;
          act(e.target, () => api('POST', 'api/users/' + encodeURIComponent(u.id) + '/split-mode', { active: !u.splitMode }));
        } }, u.splitMode ? 'Use combined address mode' : 'Use split address mode'));
    }
    actions.append(h('button', { type: 'button',
      onclick: (e) => act(e.target, () => api('POST', 'api/users/' + encodeURIComponent(u.id) + '/logout')) }, 'Sign out'));
  }
  actions.append(h('button', { class: 'danger', type: 'button',
    onclick: (e) => {
      if (!confirm('Remove ' + u.username + ' from bridge and delete its local mail cache? Mail on Proton is not affected.')) return;
      act(e.target, () => api('DELETE', 'api/users/' + encodeURIComponent(u.id)));
    } }, 'Remove account'));
  card.append(actions);
  return card;
}

function renderAccounts() {
  const box = $('accounts');
  box.replaceChildren();
  if (!state.users.length) {
    box.append(h('p', { class: 'muted' }, state.status === 'running'
      ? 'No account yet. Add your Proton account below.'
      : 'Bridge is starting…'));
    return;
  }
  for (const u of state.users) box.append(accountCard(u));
}

function field(label, attrs) {
  const input = h('input', attrs);
  return [h('label', {}, label, input), input];
}

function renderLogin() {
  const box = $('login-body');
  const l = state.login;
  const cancel = (label) => h('button', { type: 'button',
    onclick: (e) => act(e.target, () => api('DELETE', 'api/login')) }, label || 'Cancel');
  const msg = l.message ? h('p', { class: 'error' }, l.message) : null;
  box.replaceChildren();

  if (state.status !== 'running') {
    box.append(h('p', { class: 'muted' }, 'Waiting for bridge to start…'));
    return;
  }

  switch (l.stage) {
    case 'working':
      box.append(h('p', { class: 'muted' }, 'Signing in as ' + l.username + '…'), h('div', { class: 'row' }, cancel()));
      break;

    case 'tfa': {
      const [label, input] = field('Two-factor code for ' + l.username,
        { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', required: true, maxlength: '16' });
      const submit = h('button', { type: 'submit', class: 'primary' }, 'Continue');
      box.append(h('form', { onsubmit: (e) => { e.preventDefault(); act(submit, () => api('POST', 'api/login/2fa', { code: input.value })); } },
        label, h('p', { class: 'muted small' }, 'Enter the 6-digit code from your authenticator app, or a recovery code.'),
        msg, h('div', { class: 'row' }, submit, cancel())));
      input.focus();
      break;
    }

    case 'mailboxPassword': {
      const [label, input] = field('Mailbox password for ' + l.username,
        { type: 'password', autocomplete: 'off', required: true });
      const submit = h('button', { type: 'submit', class: 'primary' }, 'Continue');
      box.append(h('form', { onsubmit: (e) => { e.preventDefault(); act(submit, () => api('POST', 'api/login/mailbox-password', { password: input.value })); } },
        label, h('p', { class: 'muted small' }, 'This account uses two-password mode. Enter the second password that decrypts the mailbox.'),
        msg, h('div', { class: 'row' }, submit, cancel())));
      input.focus();
      break;
    }

    case 'hv': {
      const done = h('button', { type: 'button', class: 'primary',
        onclick: (e) => act(e.target, () => api('POST', 'api/login/verified')) }, 'I completed the verification');
      box.append(
        h('p', {}, 'Proton wants to check that you are human before signing in ' + l.username + '.'),
        h('p', {}, h('a', { class: 'button', href: l.hvUrl, target: '_blank', rel: 'noopener noreferrer' }, 'Open Proton verification')),
        h('p', { class: 'muted small' }, 'Complete the challenge in the new tab, then come back here.'),
        h('div', { class: 'row' }, done, cancel()));
      break;
    }

    case 'done':
      box.append(h('p', {}, l.message), h('div', { class: 'row' }, cancel('Add another account')));
      break;

    default: {
      const [uLabel, uInput] = field('Proton email or username',
        { type: 'text', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true, value: l.stage === 'error' ? l.username : '' });
      const [pLabel, pInput] = field('Proton password', { type: 'password', autocomplete: 'off', required: true });
      const submit = h('button', { type: 'submit', class: 'primary' }, 'Sign in to Proton');
      box.append(h('form', { onsubmit: (e) => {
        e.preventDefault();
        act(submit, () => api('POST', 'api/login', { username: uInput.value, password: pInput.value }));
      } },
        uLabel, pLabel, msg, submit,
        h('p', { class: 'muted small' },
          'The password is handed to bridge to sign in and is not stored by this page. Bridge needs a paid Proton plan.')));
    }
  }
}

function renderSettings() {
  const box = $('settings');
  const s = state.settings;
  const disabled = state.status !== 'running';
  const toggle = (key, title, help, confirmMsg) => {
    const id = 'set-' + key;
    const input = h('input', { type: 'checkbox', id, checked: !!s[key], disabled });
    input.addEventListener('change', () => {
      if (confirmMsg && !confirm(confirmMsg)) { input.checked = !input.checked; return; }
      act(input, () => api('POST', 'api/settings', { [key]: input.checked }), 'Saved');
    });
    return h('div', { class: 'setting' }, input,
      h('label', { for: id }, title, h('span', { class: 'muted' }, help)));
  };
  const reconf = 'Mail clients must be reconfigured to match after this change. Continue?';
  box.replaceChildren(...[
    // In Dovecot mode mail clients talk IMAP to Dovecot, not to bridge.
    state.dovecot ? null : toggle('imapSSL', 'IMAP: use SSL/TLS instead of STARTTLS',
      'Leave off unless your mail client cannot do STARTTLS. Both are encrypted.', reconf),
    toggle('smtpSSL', 'SMTP: use SSL/TLS instead of STARTTLS',
      'Leave off unless your mail client cannot do STARTTLS. Both are encrypted.', reconf),
    state.dovecot ? null : toggle('allMailVisible', 'Show the "All Mail" folder',
      'Turn off if your mail client downloads every message twice.'),
    toggle('telemetryDisabled', 'Disable usage statistics',
      'Stops bridge from sending anonymous usage statistics to Proton.'),
    toggle('dohEnabled', 'Allow alternative routing',
      'Lets bridge reach Proton through third-party DNS-over-HTTPS if the direct route is blocked.'),
    h('p', { class: 'muted small' }, 'Credentials are stored with the "' + (s.keychain || 'unknown') + '" keychain inside the data volume.'),
  ].filter(Boolean));
}

function renderPassword() {
  const box = $('password-body');
  if (!state.canChangePassword) {
    box.replaceChildren(h('p', { class: 'muted' },
      'The password is set through the MAILBRIDGE_PASSWORD environment variable of the container.'));
    return;
  }
  const [cLabel, cInput] = field('Current password', { type: 'password', autocomplete: 'current-password', required: true });
  const [nLabel, nInput] = field('New password (at least 10 characters)',
    { type: 'password', autocomplete: 'new-password', required: true, minlength: '10' });
  const submit = h('button', { type: 'submit' }, 'Change password');
  const form = h('form', { onsubmit: (e) => {
    e.preventDefault();
    act(submit, async () => {
      await api('POST', 'api/password', { current: cInput.value, new: nInput.value });
      form.reset();
    }, 'Password changed');
  } }, cLabel, nLabel, submit);
  box.replaceChildren(form);
}

async function loadLogs() {
  try {
    const data = await api('GET', 'api/logs');
    const pre = $('logs');
    const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 20;
    pre.textContent = data.lines.join('\n') || '(no output yet)';
    if (atBottom) pre.scrollTop = pre.scrollHeight;
  } catch (e) { /* next poll retries */ }
}

// ---------------------------------------------------------------------------
// wiring
// ---------------------------------------------------------------------------
$('signin-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('signin-error');
  err.hidden = true;
  try {
    await api('POST', 'api/session', { password: $('signin-password').value });
    $('signin-password').value = '';
    await refresh();
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  }
});

$('sign-out').addEventListener('click', async () => {
  try { await api('DELETE', 'api/session'); } catch (e) { /* already signed out */ }
  showSignIn();
});

$('btn-restart').addEventListener('click', (e) => {
  if (!confirm('Restart bridge? Mail clients are disconnected for a few seconds.')) return;
  act(e.target, () => api('POST', 'api/bridge/restart'), 'Bridge is restarting');
});

$('btn-repair').addEventListener('click', (e) => {
  if (!confirm('Repair deletes the local mail cache and downloads everything again. Continue?')) return;
  act(e.target, () => api('POST', 'api/bridge/repair'), 'Repair started');
});

$('btn-logs').addEventListener('click', (e) => {
  logsOpen = !logsOpen;
  $('logs').hidden = !logsOpen;
  e.target.textContent = logsOpen ? 'Hide bridge log' : 'Show bridge log';
  if (logsOpen) loadLogs().then(() => { $('logs').scrollTop = $('logs').scrollHeight; });
});

refresh();
