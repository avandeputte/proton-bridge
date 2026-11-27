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

// Where the browser sees this page. Behind a reverse proxy only the browser
// knows, and the container needs it to set the session cookie for the right path.
const pagePath = new URL('.', location.href).pathname;

async function api(method, path, body) {
  const opts = { method, headers: { 'X-Mailbridge': pagePath }, credentials: 'same-origin' };
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
  // A new container has no password yet: the page asks for one to be chosen.
  if (res.status === 401) needsSetup = data.setup === true;
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
let needsSetup = false;       // no password was chosen for this page yet

function show(view) {
  for (const v of ['view-loading', 'view-signin', 'view-setup', 'view-app']) $(v).hidden = v !== view;
  $('top-right').hidden = view !== 'view-app';
}

function showSignIn() {
  clearTimeout(pollTimer);
  state = null;
  rendered = {};
  revealed.clear();
  if (needsSetup) {
    if (!$('view-setup').hidden) return;
    show('view-setup');
    $('setup-password').focus();
    return;
  }
  if (!$('view-signin').hidden) return;
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
  if (changed('ports', [state.ports, state.portDefaults, state.public, state.publicDefaults, state.dovecot])) renderPorts();
  if (changed('cert', [state.certificate, state.mailCertificate, state.acme, state.acmeLocked, state.dovecot, state.publicURL])) renderCertificate();
  if (changed('password', state.canChangePassword)) renderPassword();
}

function day(t) {
  return new Date(t).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
}

function renderCertificate() {
  const c = state.certificate, acme = state.acme;
  const names = (c.names || []).filter((n) => !['127.0.0.1', '::1'].includes(n));
  const kind = {
    'self-signed': 'Self-signed certificate',
    own: 'Your own certificate' + (c.issuer ? ', issued by ' + c.issuer : ''),
    letsencrypt: 'Certificate from ' + (c.issuer || 'Let\'s Encrypt'),
  }[c.origin] || 'Certificate';
  const daysLeft = Math.floor((new Date(c.notAfter) - Date.now()) / 86400000);

  const selfSigned = c.origin === 'self-signed';
  const lines = [
    h('div', {}, h('strong', {}, kind), selfSigned ? '' : [' for ', names.flatMap((n, i) => [i ? ', ' : '', h('code', {}, n)])].flat(),
      ', valid until ' + day(c.notAfter) + '.'),
  ];
  if (!selfSigned && daysLeft < 14) {
    lines.push(h('div', { class: 'small error' }, daysLeft < 0 ? 'This certificate has expired.'
      : 'This certificate expires in ' + daysLeft + (daysLeft === 1 ? ' day.' : ' days.')));
  }

  if (acme) {
    const domains = acme.domains.join(', ');
    const next = new Date(acme.next).getTime() > 0 ? new Date(acme.next).toLocaleString() : '';
    if (acme.state === 'error') {
      lines.push(h('div', { class: 'small error' },
        (c.origin === 'letsencrypt' ? 'Renewing it failed.' : 'Getting a Let\'s Encrypt certificate for ' + domains + ' failed.') +
        (next ? ' Next attempt: ' + next + '.' : '')));
      lines.push(h('div', { class: 'sync-msg small' }, acme.message));
    } else if (c.origin !== 'letsencrypt') {
      lines.push(h('div', { class: 'small' }, (acme.message || 'Requesting a Let\'s Encrypt certificate.') +
        ' The self-signed certificate is used until it arrives.'));
    } else {
      lines.push(h('div', { class: 'muted small' }, 'Renewed automatically' + (next ? '; next check ' + next : '') + '.'));
    }
  }

  const users = [];
  if (state.webTLS) users.push('this page');
  if (state.dovecot || state.mailCertificate) users.push('IMAP');
  if (state.mailCertificate) users.push('SMTP');
  const list = users.length > 1 ? users.slice(0, -1).join(', ') + ' and ' + users[users.length - 1] : users[0];
  const plain = state.publicURL ? 'This page is served through ' + state.publicURL + '. ' : 'This page is served without encryption. ';
  const who = (users.length ? list[0].toUpperCase() + list.slice(1) + (users.length > 1 ? ' present' : ' presents') +
    ' this certificate. ' : '') + (state.webTLS ? '' : plain);
  let note;
  if (state.mailCertificate && selfSigned) {
    note = who + 'Browsers and mail clients will ask you to accept it.';
  } else if (state.mailCertificate) {
    note = who + 'Mail clients accept it without asking as long as they connect by one of the names above.';
  } else if (state.dovecot) {
    note = who + 'SMTP presents bridge\'s own self-signed certificate, which you can download below. Mail clients ' +
      'will ask you to accept both.';
  } else {
    note = who + 'IMAP and SMTP present bridge\'s own self-signed certificate: mail clients will ask you to accept ' +
      'it, and you can download it below if your client needs it installed first.';
  }
  lines.push(h('div', { class: 'muted small' }, note));

  $('certificate').replaceChildren(...lines);
  $('btn-cert').hidden = state.mailCertificate;

  // --- Let's Encrypt set-up ---
  const actions = $('acme-actions');
  actions.replaceChildren();
  if (state.acmeLocked === 'environment') {
    actions.append(h('span', { class: 'muted small' },
      'Let\'s Encrypt is set up with the MAILBRIDGE_ACME_ variables of the container. Change it there.'));
  } else if (state.acmeLocked === 'certificate') {
    actions.append(h('span', { class: 'muted small' },
      'The certificate comes from the files in MAILBRIDGE_TLS_CERT and MAILBRIDGE_TLS_KEY. Remove those to use Let\'s Encrypt.'));
  } else {
    actions.append(h('button', { type: 'button', onclick: openAcmeForm },
      acme ? 'Change Let\'s Encrypt settings' : 'Get a certificate from Let\'s Encrypt'));
  }
  if (acme && acme.state === 'error') {
    actions.append(h('button', { type: 'button',
      onclick: (e) => act(e.target, () => api('POST', 'api/acme/retry'), 'Trying again') }, 'Try again now'));
  }
}

// The form is filled once when it opens, and not touched by the refreshes of
// the page after that: someone is typing in it.
async function openAcmeForm() {
  const box = $('acme-form');
  let cfg;
  try {
    cfg = await api('GET', 'api/acme');
  } catch (e) {
    if (e.status === 401) showSignIn(); else toast(e.message);
    return;
  }

  const [dLabel, dInput] = field('Domain name', { type: 'text', required: true, placeholder: 'mail.example.com',
    value: cfg.domains.join(', '), autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' });
  dLabel.append(h('span', { class: 'hint' }, 'The name your devices use for this server. It has to be in a domain you own. ' +
    'Several names separated by commas work, and so do wildcards such as *.example.com.'));

  const [pLabel, pInput] = field('DNS provider of the domain', { type: 'text', required: true, list: 'acme-providers',
    placeholder: 'cloudflare', value: cfg.dns, autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' });
  pLabel.append(h('datalist', { id: 'acme-providers' }, cfg.providers.map((c) => h('option', { value: c }))),
    h('span', { class: 'hint' }, 'The company that hosts the DNS records of the domain. Start typing to search ' +
      (cfg.providers.length || 'the') + ' supported providers.'));

  // What was typed or forgotten, by variable name, so that it survives
  // switching back and forth between providers.
  const typed = {};
  const forgotten = new Set();
  // Whether to hide a value while it is typed: credentials unless they are
  // plainly not secret, the other settings only if they sound like one.
  const secretName = /PASS|SECRET|TOKEN|KEY|CREDENTIAL|HMAC/;
  const plainName = /EMAIL|REGION|ENDPOINT|URL|USER|MODE|ZONE_ID|HOST|PROFILE|_ID$/;
  const provBox = h('div', { class: 'acme-provider' });
  let loaded = '';

  const variable = (v, secret) => {
    const isSet = cfg.set.includes(v.name) && pInput.value.trim() === cfg.dns && !forgotten.has(v.name);
    const input = h('input', { type: secret ? 'password' : 'text', autocomplete: secret ? 'new-password' : 'off',
      autocapitalize: 'none', spellcheck: 'false', value: typed[v.name] || '',
      placeholder: isSet ? 'saved, leave empty to keep it' : '' });
    input.addEventListener('input', () => { typed[v.name] = input.value; });
    const label = h('label', {}, h('code', {}, v.name), input, h('span', { class: 'hint' }, v.description,
      isSet ? [' ', h('button', { class: 'link small', type: 'button', onclick: () => { forgotten.add(v.name); showProvider(true); } },
        'Forget the saved value')] : null));
    return label;
  };

  async function showProvider(again) {
    const code = pInput.value.trim().toLowerCase();
    if (code === loaded && !again) return;
    loaded = code;
    if (!code) { provBox.replaceChildren(); return; }
    let info;
    try {
      info = await api('GET', 'api/acme/providers/' + encodeURIComponent(code));
    } catch (e) {
      if (loaded === code) provBox.replaceChildren(h('p', { class: 'small error' }, e.message));
      return;
    }
    if (loaded !== code) return; // the user typed on meanwhile
    provBox.replaceChildren(...[
      h('p', { class: 'small' }, h('strong', {}, info.name), ': fill in what the provider gave you. Most need just one ' +
        'API token, and the rest stays empty. ',
        info.url ? h('a', { href: info.url, target: '_blank', rel: 'noopener noreferrer' }, 'What each one means') : null),
      // Several providers know their credentials by a second name as well. One is enough here.
      ...info.credentials.filter((v) => !/^Alias (to|of) /i.test(v.description) || cfg.set.includes(v.name))
        .map((v) => variable(v, !plainName.test(v.name))),
      info.options.length ? h('details', {}, h('summary', {}, 'More settings of this provider'),
        info.options.map((v) => variable(v, secretName.test(v.name)))) : null,
    ].filter(Boolean));
  }
  pInput.addEventListener('change', () => showProvider(false));
  pInput.addEventListener('blur', () => showProvider(false));

  const [eLabel, eInput] = field('Contact address (optional)', { type: 'email', value: cfg.email, autocomplete: 'off',
    placeholder: 'you@example.com' });
  eLabel.append(h('span', { class: 'hint' }, 'Registered with the Let\'s Encrypt account.'));

  const stagingId = 'acme-staging';
  const staging = h('input', { type: 'checkbox', id: stagingId, checked: !!cfg.staging });
  const stagingRow = h('div', { class: 'setting' }, staging, h('label', { for: stagingId }, 'Test mode',
    h('span', { class: 'muted' }, 'Gets a test certificate, which browsers and mail clients do not trust, from Let\'s Encrypt\'s ' +
      'staging server. Use it until everything works: the real server only allows a few failed attempts per hour.')));

  const [rLabel, rInput] = field('DNS resolver', { type: 'text', value: cfg.resolvers.join(', '), placeholder: '1.1.1.1:53',
    autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' });
  rLabel.append(h('span', { class: 'hint' }, 'Only needed when the DNS server of your network answers for the whole domain ' +
    'itself, which hides the real name servers.'));

  const close = () => { box.hidden = true; box.replaceChildren(); };
  const split = (v) => v.split(/[\s,]+/).filter(Boolean);
  const save = h('button', { class: 'primary', type: 'submit' }, 'Save and request the certificate');
  const form = h('form', { onsubmit: (e) => {
    e.preventDefault();
    const sameProvider = pInput.value.trim().toLowerCase() === cfg.dns;
    const variables = {};
    for (const [name, value] of Object.entries(typed)) if (value) variables[name] = value;
    act(save, async () => {
      await api('POST', 'api/acme', {
        domains: split(dInput.value), dns: pInput.value.trim().toLowerCase(), email: eInput.value.trim(),
        staging: staging.checked, resolvers: split(rInput.value), variables,
        keep: sameProvider ? cfg.set.filter((n) => !forgotten.has(n) && !variables[n]) : [],
      });
      close();
    }, 'Saved. Requesting the certificate.');
  } }, dLabel, pLabel, provBox, eLabel, stagingRow, h('details', {}, h('summary', {}, 'Advanced'), rLabel),
    h('div', { class: 'row' }, save,
      cfg.domains.length ? h('button', { class: 'danger', type: 'button', onclick: (e) => {
        if (!confirm('Stop using Let\'s Encrypt and go back to the self-signed certificate?')) return;
        act(e.target, async () => { await api('DELETE', 'api/acme'); close(); }, 'Let\'s Encrypt is turned off');
      } }, 'Turn off Let\'s Encrypt') : null,
      h('button', { type: 'button', onclick: close }, 'Cancel')));

  box.replaceChildren(form);
  box.hidden = false;
  showProvider(false);
  dInput.focus();
}

function renderPorts() {
  const p = state.ports, d = state.portDefaults, pub = state.public, pd = state.publicDefaults;
  const listen = {}, shown = {};
  const port = (into, key, label, value, placeholder) => {
    into[key] = h('input', { type: 'number', min: '1', max: '65535', inputmode: 'numeric',
      value: value ? String(value) : '', placeholder: placeholder || 'off' });
    return h('label', {}, label, into[key]);
  };
  const url = h('input', { type: 'url', class: 'wide', value: pub.url || '', autocomplete: 'off', spellcheck: 'false',
    placeholder: pd.url || 'https://mail.example.com' });
  const host = h('input', { type: 'text', class: 'wide', value: pub.host || '', autocomplete: 'off', spellcheck: 'false',
    autocapitalize: 'none', placeholder: pd.host });
  const save = h('button', { type: 'submit' }, 'Save ports and addresses');
  const form = h('form', { class: 'ports', onsubmit: (e) => {
    e.preventDefault();
    const body = { ports: {}, public: { url: url.value.trim(), host: host.value.trim() } };
    for (const [key, input] of Object.entries(listen)) body.ports[key] = input.value ? Number(input.value) : 0;
    for (const [key, input] of Object.entries(shown)) body.public[key] = input.value ? Number(input.value) : 0;
    act(save, () => api('POST', 'api/addresses', body), 'Ports and addresses saved');
  } },
    h('h3', {}, 'Ports this container listens on'),
    h('div', { class: 'row' }, port(listen, 'imap', 'IMAP', p.imap, d.imap),
      state.dovecot ? port(listen, 'imaps', 'IMAP with SSL/TLS', p.imaps, d.imaps) : null,
      port(listen, 'smtp', 'SMTP', p.smtp, d.smtp)),
    h('p', { class: 'muted small' }, 'Leave a field empty for the port shown in grey. A port set here is opened in addition ' +
      'to that one. If Docker publishes the container\'s ports, publish the new one too, for example "2143:2143".'),
    h('h3', {}, 'Addresses that browsers and mail clients use'),
    h('p', { class: 'muted small' }, 'Fill these in when they differ from where the container listens: behind a reverse ' +
      'proxy, behind a TCP proxy for IMAP and SMTP, or with ports published under other numbers. They are what this page ' +
      'shows and what goes into profiles. Setting them opens no port.'),
    h('label', {}, 'Address of this page', url,
      h('span', { class: 'hint' }, 'The address of the reverse proxy, with the path if there is one, such as ' +
        'https://example.com/mailbridge. The page keeps working at the container\'s own address.')),
    h('label', {}, 'Mail server name', host,
      h('span', { class: 'hint' }, 'The name mail clients connect to. Empty uses the name in grey.')),
    h('div', { class: 'row' }, port(shown, 'imap', 'IMAP port', pub.imap, pd.imap),
      state.dovecot ? port(shown, 'imaps', 'IMAP with SSL/TLS port', pub.imaps, pd.imaps) : null,
      port(shown, 'smtp', 'SMTP port', pub.smtp, pd.smtp)),
    h('div', { class: 'row' }, save));
  $('ports').replaceChildren(form);
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
  if (u.state === 'connected') {
    actions.append(h('a', { class: 'button', href: 'api/users/' + encodeURIComponent(u.id) + '/profile', download: '',
      title: 'A configuration profile that sets this account up in Mail on iPhone, iPad and Mac. It contains the password above.' },
      'Profile for iPhone, iPad and Mac'));
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
    if (needsSetup) { showSignIn(); return; }
    err.textContent = ex.message;
    err.hidden = false;
  }
});

$('setup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('setup-error');
  const fail = (msg) => { err.textContent = msg; err.hidden = false; };
  err.hidden = true;
  if ($('setup-password').value !== $('setup-repeat').value) {
    fail('The two passwords are not the same.');
    return;
  }
  try {
    await api('POST', 'api/setup', { password: $('setup-password').value });
    needsSetup = false;
    e.target.reset();
    await refresh();
  } catch (ex) {
    if (ex.status !== 409) { fail(ex.message); return; }
    // Somebody else was first: the password is theirs to know.
    e.target.reset();
    needsSetup = false;
    showSignIn();
    $('signin-error').textContent = ex.message;
    $('signin-error').hidden = false;
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
