/*
 * Tarjeta de coordenadas — PWA sin conexión.
 *
 * Cifrado (dos capas):
 *  1. Capa del PIN (portátil, es la que va en la copia de seguridad):
 *     clave AES-GCM-256 derivada del PIN con PBKDF2-SHA256 (600.000 iteraciones,
 *     sal aleatoria de 16 bytes). El PIN no se guarda en ningún sitio: si es
 *     incorrecto, el descifrado falla.
 *  2. Capa del dispositivo: la capa anterior se vuelve a cifrar con una clave
 *     AES-GCM-256 generada en este navegador como NO exportable y guardada en
 *     IndexedDB. Copiar los datos guardados a otro aparato no sirve sin ella.
 *
 * Tras 5 PIN incorrectos seguidos se borra todo. El contador se incrementa
 * ANTES de comprobar el PIN, para que cerrar la app a medias no lo esquive.
 */
'use strict';

const CONFIG = {
  ROWS: 'ABCDEFGHIJ',
  COLS: 10,
  PIN_LENGTH: 6,
  MAX_FAILS: 5,
  LOCK_AFTER_MS: 3 * 60 * 1000,
  PBKDF2_ITER: 600000,
  APP_ID: 'tarjeta-coordenadas',
  FORMAT_VERSION: 1,
};
const CELLS = CONFIG.ROWS.length * CONFIG.COLS;
const AAD = new TextEncoder().encode(`${CONFIG.APP_ID}:v${CONFIG.FORMAT_VERSION}`);

/* ================= Utilidades ================= */
const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

function b64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function unb64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

/* ================= Almacenamiento (IndexedDB) ================= */
const store = (() => {
  let dbp;
  function open() {
    if (!dbp) {
      dbp = new Promise((resolve, reject) => {
        const req = indexedDB.open(CONFIG.APP_ID, 1);
        req.onupgradeneeded = () => req.result.createObjectStore('kv');
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }
    return dbp;
  }
  async function run(mode, fn) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('kv', mode);
      const req = fn(tx.objectStore('kv'));
      tx.oncomplete = () => resolve(req ? req.result : undefined);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  }
  return {
    get: (k) => run('readonly', (s) => s.get(k)),
    set: (k, v) => run('readwrite', (s) => s.put(v, k)),
    clear: () => run('readwrite', (s) => s.clear()),
  };
})();

/* ================= Criptografía ================= */
async function derivePinKey(pin, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Cifra la matriz con la clave del PIN. Devuelve el objeto portátil (copia de seguridad). */
async function sealWithPin(matrix, key, salt, iterations) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: AAD },
    key,
    enc.encode(JSON.stringify({ m: matrix })),
  );
  return {
    app: CONFIG.APP_ID,
    v: CONFIG.FORMAT_VERSION,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iter: iterations },
    salt: b64(salt),
    iv: b64(iv),
    ct: b64(ct),
  };
}

/** Lanza un error con code 'BAD_PIN' si el PIN no es el correcto. */
async function openWithPin(blob, pin) {
  const salt = unb64(blob.salt);
  const iterations = blob.kdf.iter;
  const key = await derivePinKey(pin, salt, iterations);
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(blob.iv), additionalData: AAD },
      key,
      unb64(blob.ct),
    );
  } catch {
    const err = new Error('PIN incorrecto');
    err.code = 'BAD_PIN';
    throw err;
  }
  const matrix = JSON.parse(dec.decode(plain)).m;
  if (!isValidMatrix(matrix)) throw new Error('Contenido no válido');
  return { matrix, key, salt, iterations };
}

function isValidBlob(b) {
  return b && b.app === CONFIG.APP_ID && b.v === CONFIG.FORMAT_VERSION &&
    b.kdf && b.kdf.name === 'PBKDF2' && Number.isInteger(b.kdf.iter) && b.kdf.iter >= 100000 &&
    typeof b.salt === 'string' && typeof b.iv === 'string' && typeof b.ct === 'string';
}
function isValidMatrix(m) {
  return Array.isArray(m) && m.length === CELLS && m.every((v) => /^\d{2}$/.test(v));
}

async function getDeviceKey(create) {
  let key = await store.get('deviceKey');
  if (!key && create) {
    key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    await store.set('deviceKey', key);
  }
  return key;
}

/** Guarda el objeto portátil envuelto con la clave del dispositivo. */
async function saveVault(blob) {
  const deviceKey = await getDeviceKey(true);
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, deviceKey, enc.encode(JSON.stringify(blob)));
  await store.set('vault', { iv, ct });
  await store.set('fails', 0);
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
}

async function loadVault() {
  const vault = await store.get('vault');
  if (!vault) return null;
  const deviceKey = await getDeviceKey(false);
  if (!deviceKey) throw Object.assign(new Error('Falta la clave del dispositivo'), { code: 'CORRUPT' });
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: vault.iv }, deviceKey, vault.ct);
    return JSON.parse(dec.decode(plain));
  } catch {
    throw Object.assign(new Error('Datos dañados'), { code: 'CORRUPT' });
  }
}

async function wipeAll() {
  endSession();
  await store.clear();
}

/* ================= Sesión ================= */
// Solo existe mientras la app está desbloqueada; se descarta al bloquear.
let session = null;
let lastActivity = Date.now();
let tickTimer = null;

function startSession(data, blob) {
  session = { matrix: data.matrix, key: data.key, salt: data.salt, iterations: data.iterations, blob };
  markActivity();
  clearInterval(tickTimer);
  tickTimer = setInterval(tick, 1000);
  tick();
}

function endSession() {
  if (session && session.matrix) session.matrix.fill('');
  session = null;
  clearInterval(tickTimer);
  tickTimer = null;
  clearResult();
  draft = null;
}

function markActivity() { lastActivity = Date.now(); }

function tick() {
  if (!session) return;
  const left = CONFIG.LOCK_AFTER_MS - (Date.now() - lastActivity);
  if (left <= 0) { lock(); return; }
  const s = Math.ceil(left / 1000);
  const el = $('countdown');
  el.textContent = `Se bloquea en ${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} sin actividad`;
  el.classList.toggle('soon', s <= 30);
}

function lock() {
  if (!session) return;
  endSession();
  closeDialog();
  pin.abort();
  unlockFlow();
}

['pointerdown', 'keydown', 'input', 'touchstart'].forEach((ev) =>
  document.addEventListener(ev, markActivity, { passive: true, capture: true }));
document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });

/* ================= Pantallas ================= */
function show(id) {
  document.querySelectorAll('.screen').forEach((s) => { s.hidden = s.id !== id; });
  window.scrollTo(0, 0);
}

let toastTimer;
function toast(text) {
  const t = $('toast');
  t.textContent = text;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

/* Diálogo de confirmación */
let dialogResolve = null;
function confirmDialog({ title, text, ok = 'Aceptar', cancel = 'Cancelar', danger = false }) {
  const dlg = $('dlg');
  $('dlg-title').textContent = title;
  $('dlg-text').textContent = text;
  $('dlg-ok').textContent = ok;
  $('dlg-ok').className = `btn ${danger ? 'btn--danger' : 'btn--primary'}`;
  $('dlg-cancel').hidden = cancel === null;
  $('dlg-cancel').textContent = cancel || '';
  dlg.querySelector('.dlg__actions').classList.toggle('single', cancel === null);
  return new Promise((resolve) => {
    dialogResolve = resolve;
    dlg.returnValue = '';
    dlg.showModal();
  });
}
$('dlg').addEventListener('close', () => {
  if (dialogResolve) { const r = dialogResolve; dialogResolve = null; r($('dlg').returnValue === 'ok'); }
});
function closeDialog() { const d = $('dlg'); if (d.open) d.close('cancel'); }

/* ================= Teclado de PIN ================= */
const pin = (() => {
  let value = '';
  let resolver = null;
  let busy = false;
  const dots = $('pin-dots');
  const pad = $('keypad');

  function render() {
    [...dots.children].forEach((d, i) => d.classList.toggle('on', i < value.length));
  }
  function press(k) {
    if (!resolver || busy) return;
    if (k === 'del') value = value.slice(0, -1);
    else if (value.length < CONFIG.PIN_LENGTH) value += k;
    render();
    if (value.length === CONFIG.PIN_LENGTH) {
      const v = value;
      const r = resolver;
      resolver = null;
      setTimeout(() => r(v), 90); // deja ver el último punto
    }
  }
  pad.addEventListener('click', (e) => {
    const b = e.target.closest('button[data-k]');
    if (b) press(b.dataset.k);
  });
  document.addEventListener('keydown', (e) => {
    if ($('s-pin').hidden || $('dlg').open) return;
    if (/^\d$/.test(e.key)) press(e.key);
    else if (e.key === 'Backspace') press('del');
  });
  $('pin-cancel').addEventListener('click', () => {
    if (resolver && !busy) { const r = resolver; resolver = null; r(null); }
  });

  return {
    /** Muestra el teclado y resuelve con el PIN tecleado, o null si se cancela. */
    ask({ title, sub = '', error = '', cancelable = false }) {
      value = '';
      busy = false;
      render();
      dots.classList.remove('busy');
      pad.classList.remove('busy');
      $('pin-title').textContent = title;
      $('pin-sub').textContent = sub;
      $('pin-msg').textContent = error;
      $('pin-cancel').hidden = !cancelable;
      if (error) { dots.classList.remove('shake'); void dots.offsetWidth; dots.classList.add('shake'); }
      show('s-pin');
      return new Promise((resolve) => { resolver = resolve; });
    },
    setBusy(on, text) {
      busy = on;
      dots.classList.toggle('busy', on);
      pad.classList.toggle('busy', on);
      if (on) $('pin-msg').textContent = text || 'Comprobando…';
    },
    abort() {
      if (resolver) { const r = resolver; resolver = null; r(null); }
    },
  };
})();

function isWeakPin(p) {
  if (/^(\d)\1+$/.test(p)) return true;
  return '01234567890123456'.includes(p) || '98765432109876543'.includes(p);
}

/** Pide un PIN nuevo dos veces. Devuelve el PIN o null si se cancela. */
async function chooseNewPin({ cancelable, title = 'Crea un PIN de 6 dígitos' }) {
  let error = '';
  for (;;) {
    const first = await pin.ask({
      title,
      sub: 'Lo pedirá cada vez que abras la app. No uses el PIN de tu tarjeta bancaria.',
      error,
      cancelable,
    });
    if (first === null) return null;
    if (isWeakPin(first)) { error = 'Ese PIN es muy fácil de adivinar. Elige otro.'; continue; }
    const second = await pin.ask({ title: 'Repite el PIN', sub: 'Para comprobar que lo has escrito bien.', cancelable });
    if (second === null) return null;
    if (first === second) return first;
    error = 'Los dos PIN no coinciden. Vuelve a empezar.';
  }
}

/**
 * Comprueba un PIN contra la tarjeta guardada, con contador de fallos.
 * Devuelve { ok, data, blob } | { wiped: true } | { error }.
 */
async function verifyStoredPin(p) {
  const fails = ((await store.get('fails')) || 0) + 1;
  await store.set('fails', fails);
  const blob = await loadVault();
  try {
    const data = await openWithPin(blob, p);
    await store.set('fails', 0);
    return { ok: true, data, blob };
  } catch (e) {
    if (e.code !== 'BAD_PIN') throw e;
    if (fails >= CONFIG.MAX_FAILS) {
      await wipeAll();
      return { wiped: true };
    }
    const left = CONFIG.MAX_FAILS - fails;
    return {
      error: left === 1
        ? 'PIN incorrecto. Último intento: si fallas, se borrará la tarjeta.'
        : `PIN incorrecto. Te quedan ${left} intentos.`,
    };
  }
}

/* ================= Flujos ================= */
async function boot() {
  try {
    const vault = await store.get('vault');
    if (!vault) { show('s-welcome'); return; }
    const fails = (await store.get('fails')) || 0;
    if (fails >= CONFIG.MAX_FAILS) { await wipeAll(); showWiped(); return; }
    unlockFlow();
  } catch (e) {
    console.error(e);
    showFatal('No se puede acceder al almacenamiento del navegador. Comprueba que no estás en una pestaña de incógnito.');
  }
}

function showWiped(text) {
  $('wiped-text').textContent = text ||
    `Se ha introducido un PIN incorrecto ${CONFIG.MAX_FAILS} veces seguidas, así que la tarjeta se ha borrado de este móvil.`;
  show('s-wiped');
}
function showFatal(text) {
  const s = $('s-loading');
  s.querySelector('p').textContent = text;
  show('s-loading');
}

let unlocking = false;
async function unlockFlow() {
  if (unlocking) return;
  unlocking = true;
  try {
    let error = '';
    const fails = (await store.get('fails')) || 0;
    if (fails > 0) {
      const left = CONFIG.MAX_FAILS - fails;
      error = left === 1 ? 'Último intento: si fallas, se borrará la tarjeta.' : `Te quedan ${left} intentos.`;
    }
    for (;;) {
      const p = await pin.ask({ title: 'Introduce tu PIN', error });
      if (p === null) return;
      pin.setBusy(true);
      let r;
      try {
        r = await verifyStoredPin(p);
      } catch (e) {
        if (e.code === 'CORRUPT') {
          showWiped('Los datos guardados en este móvil no se pueden leer. Restaura una copia de seguridad o vuelve a introducir la tarjeta.');
          await store.clear();
          return;
        }
        throw e;
      }
      pin.setBusy(false);
      if (r.ok) {
        startSession(r.data, r.blob);
        showMain();
        return;
      }
      if (r.wiped) { showWiped(); return; }
      error = r.error;
    }
  } finally {
    unlocking = false;
  }
}

/* ---------- Introducción de la tarjeta ---------- */
let draft = null;      // array de 100 valores mientras se introduce o edita
let draftMode = null;  // 'setup' | 'edit'
let entryRow = 0;

function buildEntryCells() {
  const wrap = $('entry-cells');
  wrap.innerHTML = '';
  for (let c = 1; c <= CONFIG.COLS; c++) {
    const f = document.createElement('div');
    f.className = 'cell-field';
    const id = `e-${c}`;
    f.innerHTML = `<label for="${id}">${c}</label>` +
      `<input id="${id}" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="2" autocomplete="off" autocorrect="off" spellcheck="false">`;
    wrap.appendChild(f);
  }
  wrap.querySelectorAll('input').forEach((inp, i, all) => {
    inp.addEventListener('input', () => {
      inp.value = inp.value.replace(/\D/g, '').slice(0, 2);
      inp.removeAttribute('aria-invalid');
      if (inp.value.length === 2) {
        if (i < all.length - 1) all[i + 1].focus();
        else $('entry-next').focus();
      }
    });
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && inp.value === '' && i > 0) { e.preventDefault(); all[i - 1].focus(); }
      if (e.key === 'Enter') { e.preventDefault(); $('entry-next').click(); }
    });
    inp.addEventListener('focus', () => inp.select());
  });
  const prog = $('rows-progress');
  prog.innerHTML = [...CONFIG.ROWS].map((r) => `<li>${r}</li>`).join('');
}

function startSetup() {
  draft = new Array(CELLS).fill('');
  draftMode = 'setup';
  entryRow = 0;
  renderEntryRow();
  show('s-entry');
  focusFirstEmpty();
}

function renderEntryRow() {
  const letter = CONFIG.ROWS[entryRow];
  $('entry-letter').textContent = letter;
  $('entry-letter-text').textContent = letter;
  $('entry-progress').textContent = `Fila ${entryRow + 1} de ${CONFIG.ROWS.length}`;
  $('entry-prev').disabled = entryRow === 0;
  $('entry-next').textContent = entryRow === CONFIG.ROWS.length - 1 ? 'Revisar' : 'Siguiente fila';
  $('entry-error').textContent = '';
  $('entry-cells').querySelectorAll('input').forEach((inp, c) => {
    inp.value = draft[entryRow * CONFIG.COLS + c];
    inp.removeAttribute('aria-invalid');
  });
  $('rows-progress').querySelectorAll('li').forEach((li, r) => {
    const done = draft.slice(r * CONFIG.COLS, (r + 1) * CONFIG.COLS).every((v) => /^\d{2}$/.test(v));
    li.className = r === entryRow ? 'current' : done ? 'done' : '';
  });
}

function focusFirstEmpty() {
  const inputs = [...$('entry-cells').querySelectorAll('input')];
  (inputs.find((i) => i.value.length < 2) || inputs[0]).focus();
}

function saveEntryRow() {
  const inputs = [...$('entry-cells').querySelectorAll('input')];
  const bad = [];
  inputs.forEach((inp, c) => {
    draft[entryRow * CONFIG.COLS + c] = inp.value;
    const ok = /^\d{2}$/.test(inp.value);
    if (!ok) { bad.push(c + 1); inp.setAttribute('aria-invalid', 'true'); }
  });
  return bad;
}

$('entry-next').addEventListener('click', () => {
  const bad = saveEntryRow();
  if (bad.length) {
    $('entry-error').textContent = bad.length === 1
      ? `Falta la columna ${bad[0]}. Cada casilla lleva 2 dígitos (por ejemplo, 05).`
      : `Faltan las columnas ${bad.join(', ')}. Cada casilla lleva 2 dígitos (por ejemplo, 05).`;
    focusFirstEmpty();
    return;
  }
  if (entryRow < CONFIG.ROWS.length - 1) {
    entryRow++;
    renderEntryRow();
    focusFirstEmpty();
  } else {
    openReview();
  }
});
$('entry-prev').addEventListener('click', () => {
  saveEntryRow();
  if (entryRow > 0) { entryRow--; renderEntryRow(); focusFirstEmpty(); }
});
$('entry-cancel').addEventListener('click', async () => {
  const any = draft && draft.some((v) => v !== '');
  if (any && !(await confirmDialog({
    title: '¿Salir sin guardar?',
    text: 'Se perderán los valores que has escrito.',
    ok: 'Salir', danger: true,
  }))) return;
  draft = null;
  show('s-welcome');
});

/* ---------- Revisión / edición ---------- */
function buildMatrixTable() {
  const t = $('review-matrix');
  let html = '<thead><tr><th></th>';
  for (let c = 1; c <= CONFIG.COLS; c++) html += `<th scope="col">${c}</th>`;
  html += '</tr></thead><tbody>';
  for (let r = 0; r < CONFIG.ROWS.length; r++) {
    html += `<tr><th scope="row">${CONFIG.ROWS[r]}</th>`;
    for (let c = 0; c < CONFIG.COLS; c++) {
      const label = `${CONFIG.ROWS[r]}${c + 1}`;
      html += `<td><input data-i="${r * CONFIG.COLS + c}" aria-label="${label}" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="2" autocomplete="off" autocorrect="off" spellcheck="false"></td>`;
    }
    html += '</tr>';
  }
  t.innerHTML = html + '</tbody>';
  const all = [...t.querySelectorAll('input')];
  all.forEach((inp, i) => {
    inp.addEventListener('input', () => {
      inp.value = inp.value.replace(/\D/g, '').slice(0, 2);
      draft[+inp.dataset.i] = inp.value;
      inp.toggleAttribute('aria-invalid', !/^\d{2}$/.test(inp.value));
      if (inp.value.length === 2 && i < all.length - 1 && inp.dataset.typed) all[i + 1].focus();
    });
    inp.addEventListener('keydown', () => { inp.dataset.typed = '1'; });
    inp.addEventListener('focus', () => { delete inp.dataset.typed; inp.select(); });
  });
}

function openReview() {
  const edit = draftMode === 'edit';
  $('review-title').textContent = edit ? 'Tu tarjeta' : 'Revisa tu tarjeta';
  $('review-lead').textContent = edit
    ? 'Toca una casilla para corregirla y guarda los cambios.'
    : 'Compara cada casilla con tu tarjeta. Toca una para corregirla.';
  $('review-save').textContent = edit ? 'Guardar cambios' : 'Guardar y crear PIN';
  $('review-error').textContent = '';
  $('review-matrix').querySelectorAll('input').forEach((inp) => {
    inp.value = draft[+inp.dataset.i];
    inp.toggleAttribute('aria-invalid', !/^\d{2}$/.test(inp.value));
  });
  show('s-review');
}

$('review-back').addEventListener('click', async () => {
  if (draftMode === 'edit') {
    const changed = draft.some((v, i) => v !== session.matrix[i]);
    if (changed && !(await confirmDialog({
      title: '¿Descartar los cambios?', text: 'La tarjeta guardada se queda como estaba.', ok: 'Descartar', danger: true,
    }))) return;
    draft = null;
    showMain();
  } else {
    entryRow = CONFIG.ROWS.length - 1;
    renderEntryRow();
    show('s-entry');
  }
});

$('review-save').addEventListener('click', async () => {
  const bad = draft.map((v, i) => (/^\d{2}$/.test(v) ? null : i)).filter((i) => i !== null);
  if (bad.length) {
    const names = bad.slice(0, 6).map((i) => `${CONFIG.ROWS[Math.floor(i / CONFIG.COLS)]}${(i % CONFIG.COLS) + 1}`);
    $('review-error').textContent = `Revisa ${names.join(', ')}${bad.length > 6 ? '…' : ''}: cada casilla lleva 2 dígitos.`;
    const first = $('review-matrix').querySelector(`input[data-i="${bad[0]}"]`);
    if (first) first.focus();
    return;
  }
  if (draftMode === 'edit') {
    if (!session) return;
    const blob = await sealWithPin(draft.slice(), session.key, session.salt, session.iterations);
    await saveVault(blob);
    session.matrix = draft.slice();
    session.blob = blob;
    draft = null;
    showMain();
    toast('Cambios guardados');
    return;
  }
  // Configuración inicial: crear PIN, cifrar y guardar.
  const matrix = draft.slice();
  const p = await chooseNewPin({ cancelable: true });
  if (p === null) { openReview(); return; }
  pin.setBusy(true, 'Cifrando la tarjeta…');
  const salt = rand(16);
  const key = await derivePinKey(p, salt, CONFIG.PBKDF2_ITER);
  const blob = await sealWithPin(matrix, key, salt, CONFIG.PBKDF2_ITER);
  await saveVault(blob);
  draft.fill('');
  draft = null;
  startSession({ matrix, key, salt, iterations: CONFIG.PBKDF2_ITER }, blob);
  showMain();
  toast('Tarjeta guardada y cifrada');
  offerFirstBackup();
});

async function offerFirstBackup() {
  const yes = await confirmDialog({
    title: '¿Hacer una copia de seguridad?',
    text: 'Si borras los datos del navegador o cambias de móvil, la necesitarás para recuperar la tarjeta. Puedes hacerla más tarde desde el menú.',
    ok: 'Exportar ahora', cancel: 'Más tarde',
  });
  if (yes) exportBackup();
}

/* ---------- Consulta ---------- */
function buildMiniGrid() {
  const g = $('minigrid');
  let html = '<span></span>';
  for (let c = 1; c <= CONFIG.COLS; c++) html += `<b data-col="${c - 1}">${c}</b>`;
  for (let r = 0; r < CONFIG.ROWS.length; r++) {
    html += `<b data-row="${r}">${CONFIG.ROWS[r]}</b>`;
    for (let c = 0; c < CONFIG.COLS; c++) html += `<i data-r="${r}" data-c="${c}"></i>`;
  }
  g.innerHTML = html;
}

function parseCoord(raw) {
  const s = raw.toUpperCase().replace(/[\s\-.,:/]/g, '');
  const m = s.match(/^([A-J])(10|[1-9])$/) || s.match(/^(10|[1-9])([A-J])$/);
  if (!m) return null;
  const letter = /[A-J]/.test(m[1]) ? m[1] : m[2];
  const col = Number(/[A-J]/.test(m[1]) ? m[2] : m[1]);
  return { row: CONFIG.ROWS.indexOf(letter), col: col - 1, label: `${letter}${col}` };
}

function showMain() {
  show('s-main');
  tick();
  const inp = $('coord');
  inp.value = '';
  $('query-error').textContent = '';
  setTimeout(() => inp.focus(), 50);
}

function clearResult() {
  $('result').hidden = true;
  $('empty').hidden = false;
  $('result-value').textContent = '';
  $('coord').value = '';
}

$('query-form').addEventListener('submit', (e) => {
  e.preventDefault();
  if (!session) return;
  const inp = $('coord');
  const c = parseCoord(inp.value);
  if (!c) {
    $('query-error').textContent = inp.value.trim()
      ? 'Escribe una letra de la A a la J y un número del 1 al 10, por ejemplo C7.'
      : 'Escribe una coordenada, por ejemplo C7.';
    inp.select();
    return;
  }
  $('query-error').textContent = '';
  $('result-coord').textContent = c.label;
  $('result-value').textContent = session.matrix[c.row * CONFIG.COLS + c.col];
  $('minigrid').querySelectorAll('i').forEach((d) => {
    const r = +d.dataset.r, col = +d.dataset.c;
    d.className = r === c.row && col === c.col ? 'hit' : r === c.row ? 'hit-row' : col === c.col ? 'hit-col' : '';
  });
  $('minigrid').querySelectorAll('b').forEach((b) => {
    const isRow = 'row' in b.dataset && +b.dataset.row === c.row;
    const isCol = 'col' in b.dataset && +b.dataset.col === c.col;
    b.classList.toggle('on', isRow || isCol);
  });
  const res = $('result');
  res.hidden = false;
  $('empty').hidden = true;
  res.classList.remove('flash'); void res.offsetWidth; res.classList.add('flash');
  inp.value = '';
  inp.focus();
});
$('coord').addEventListener('input', () => { $('query-error').textContent = ''; });

$('main-lock').addEventListener('click', lock);
$('main-menu').addEventListener('click', () => show('s-menu'));
$('menu-back').addEventListener('click', showMain);

/* ---------- Menú ---------- */
$('m-edit').addEventListener('click', () => {
  if (!session) return;
  draft = session.matrix.slice();
  draftMode = 'edit';
  openReview();
});

$('m-pin').addEventListener('click', async () => {
  if (!session) return;
  let error = '';
  for (;;) {
    const current = await pin.ask({ title: 'PIN actual', sub: 'Para cambiarlo, primero escribe el que usas ahora.', error, cancelable: true });
    if (current === null || !session) { if (session) show('s-menu'); return; }
    pin.setBusy(true);
    const r = await verifyStoredPin(current);
    pin.setBusy(false);
    if (r.wiped) { showWiped(); return; }
    if (r.ok) break;
    error = r.error;
  }
  const next = await chooseNewPin({ cancelable: true, title: 'Nuevo PIN de 6 dígitos' });
  if (next === null || !session) { if (session) show('s-menu'); return; }
  pin.setBusy(true, 'Cifrando con el PIN nuevo…');
  const salt = rand(16);
  const key = await derivePinKey(next, salt, CONFIG.PBKDF2_ITER);
  const blob = await sealWithPin(session.matrix, key, salt, CONFIG.PBKDF2_ITER);
  await saveVault(blob);
  Object.assign(session, { key, salt, iterations: CONFIG.PBKDF2_ITER, blob });
  showMain();
  toast('PIN cambiado');
  const again = await confirmDialog({
    title: 'Las copias antiguas usan el PIN anterior',
    text: 'Si quieres una copia de seguridad con el PIN nuevo, expórtala ahora.',
    ok: 'Exportar ahora', cancel: 'Más tarde',
  });
  if (again) exportBackup();
});

$('m-export').addEventListener('click', () => exportBackup());

async function exportBackup() {
  if (!session) return;
  const ok = await confirmDialog({
    title: 'Exportar copia de seguridad',
    text: 'El archivo está cifrado con tu PIN actual. Fuera de esta app no hay límite de intentos, así que muévelo a un sitio que solo controles tú (por ejemplo, un pendrive o una carpeta privada) y bórralo de Descargas.',
    ok: 'Descargar archivo',
  });
  if (!ok || !session) return;
  const json = JSON.stringify(session.blob, null, 2);
  const d = new Date();
  const name = `tarjeta-coordenadas-${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}.json`;
  const url = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  toast('Copia descargada');
}

/* ---------- Restaurar copia ---------- */
let importOrigin = null; // pantalla a la que volver si se cancela
function pickBackup(origin) {
  importOrigin = origin;
  const f = $('file-import');
  f.value = '';
  f.click();
}
$('welcome-import').addEventListener('click', () => pickBackup('s-welcome'));
$('wiped-import').addEventListener('click', () => pickBackup('s-wiped'));
$('m-import').addEventListener('click', () => pickBackup('s-menu'));

$('file-import').addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  const back = () => {
    if (importOrigin === 's-menu') { if (session) show('s-menu'); } // si se bloqueó, ya está en el PIN
    else show(importOrigin || 's-welcome');
  };
  let blob;
  try {
    if (file.size > 100000) throw new Error('grande');
    blob = JSON.parse(await file.text());
    if (!isValidBlob(blob)) throw new Error('formato');
  } catch {
    await confirmDialog({
      title: 'Archivo no válido',
      text: 'Ese archivo no es una copia de seguridad de esta app.',
      ok: 'Entendido', cancel: null,
    });
    return;
  }
  if (importOrigin === 's-menu' && session) {
    const sure = await confirmDialog({
      title: '¿Sustituir la tarjeta actual?',
      text: 'La tarjeta guardada en este móvil se reemplazará por la de la copia, y el PIN pasará a ser el de la copia.',
      ok: 'Sustituir', danger: true,
    });
    if (!sure || !session) return;
  }
  let error = '';
  for (;;) {
    const p = await pin.ask({
      title: 'PIN de la copia',
      sub: 'El que tenías cuando hiciste la copia de seguridad.',
      error, cancelable: true,
    });
    if (p === null) { back(); return; }
    pin.setBusy(true);
    try {
      const data = await openWithPin(blob, p);
      await saveVault(blob);
      endSession();
      startSession(data, blob);
      showMain();
      toast('Copia restaurada');
      return;
    } catch (err) {
      pin.setBusy(false);
      if (err.code !== 'BAD_PIN') {
        await confirmDialog({ title: 'No se pudo restaurar', text: 'La copia está dañada o no es de esta app.', ok: 'Entendido', cancel: null });
        back();
        return;
      }
      error = 'Ese no es el PIN de esta copia. Prueba otra vez.';
    }
  }
});

/* ---------- Borrar ---------- */
$('m-wipe').addEventListener('click', async () => {
  const ok = await confirmDialog({
    title: '¿Borrar la tarjeta de este móvil?',
    text: 'Solo podrás recuperarla con una copia de seguridad o volviendo a introducirla.',
    ok: 'Borrar', danger: true,
  });
  if (!ok) return;
  await wipeAll();
  show('s-welcome');
  toast('Datos borrados');
});

/* ---------- Bienvenida ---------- */
$('welcome-setup').addEventListener('click', startSetup);
$('wiped-setup').addEventListener('click', startSetup);

/* ---------- Instalación ---------- */
let installPrompt = null;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  installPrompt = e;
  $('welcome-install').hidden = false;
  $('m-install').hidden = false;
});
window.addEventListener('appinstalled', () => {
  installPrompt = null;
  $('welcome-install').hidden = true;
  $('m-install').hidden = true;
});
async function doInstall() {
  if (!installPrompt) return;
  installPrompt.prompt();
  await installPrompt.userChoice.catch(() => {});
  installPrompt = null;
  $('welcome-install').hidden = true;
  $('m-install').hidden = true;
}
$('welcome-install').addEventListener('click', doInstall);
$('m-install').addEventListener('click', doInstall);

/* ================= Arranque ================= */
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => navigator.serviceWorker.register('./sw.js').catch(() => {}));
}

buildEntryCells();
buildMatrixTable();
buildMiniGrid();

if (!window.isSecureContext || !crypto.subtle || !window.indexedDB) {
  showFatal('Este navegador no permite el cifrado necesario. Abre la app desde su dirección https:// en Chrome.');
} else {
  boot();
}
