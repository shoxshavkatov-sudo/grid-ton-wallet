/* GRID WALLET — non-custodial TON wallet (Tonkeeper-style).
   Keys are generated client-side from a 24-word TON mnemonic, encrypted with
   the user's password (PBKDF2 + AES-GCM), and never leave this device.
   Transfers are signed in-browser and broadcast to the TON network. */
'use strict';
import { TonClient, WalletContractV4, internal } from '@ton/ton';
import { mnemonicNew, mnemonicValidate, mnemonicToPrivateKey } from '@ton/crypto';
import { Address, toNano, fromNano } from '@ton/core';

// ---------------------------------------------------------------- i18n
const I18N = {
  en: {
    tabWallet: 'WALLET', tabActivity: 'ACTIVITY', tabSettings: 'SETTINGS',
    tagline: 'your keys, your crypto — on TON',
    createWallet: 'CREATE NEW WALLET', importWallet: 'IMPORT WALLET',
    setPassword: 'set a password', unlock: 'UNLOCK', password: 'password',
    passNote: 'the password encrypts your 24-word seed on this device. 6+ chars.',
    seedTitle: 'Your recovery phrase', seedNote: 'write these 24 words on paper and keep them offline. anyone with them owns your wallet. they are shown once.',
    savedIt: 'I saved the phrase', importTitle: 'Import wallet', seedPlaceholder: 'paste your 24 words…', importBtn: 'IMPORT',
    badSeed: 'invalid recovery phrase', wrongPass: 'wrong password', unlockTitle: 'Unlock wallet',
    receive: 'RECEIVE', send: 'SEND', scanToPay: 'send only TON to this address',
    sendTitle: 'Send TON', recipient: 'recipient address', amountTons: 'amount, TON', comment: 'comment (optional)',
    feeNote: 'network fee ≈ 0.01–0.05 TON', sendBtn: 'SEND', badAddr: 'invalid TON address',
    lowBalance: 'not enough TON (keep a little for fees)', sent: '✓ sent to the network',
    historyTitle: 'Activity', noHistory: 'no transactions yet', in_: 'IN', out_: 'OUT',
    settingsTitle: 'SETTINGS', showSeed: 'SHOW RECOVERY PHRASE', logout: 'LOG OUT',
    wipe: 'wipe wallet from this device? you will need the 24 words to restore it.',
    jettons: 'Tokens', activate: 'send ≥ 0.05 TON to activate the wallet',
    balance: 'BALANCE', address: 'ADDRESS', yourAddress: 'your TON address', copy: 'copy', copied: 'copied',
    footer: 'GRID WALLET — non-custodial TON wallet. Your keys, your crypto. Grid Tech is not responsible for lost seed phrases.',
  },
  ru: {
    tabWallet: 'КОШЕЛЁК', tabActivity: 'АКТИВНОСТЬ', tabSettings: 'НАСТРОЙКИ',
    tagline: 'твои ключи — твоя крипта, на TON',
    createWallet: 'СОЗДАТЬ НОВЫЙ КОШЕЛЁК', importWallet: 'ИМПОРТИРОВАТЬ КОШЕЛЁК',
    setPassword: 'придумай пароль', unlock: 'ОТКРЫТЬ', password: 'пароль',
    passNote: 'пароль шифрует seed-фразу из 24 слов на этом устройстве. от 6 символов.',
    seedTitle: 'Твоя фраза восстановления', seedNote: 'запиши эти 24 слова на бумаге и храни офлайн. у кого фраза — у того и кошелёк. показывается один раз.',
    savedIt: 'Я записал фразу', importTitle: 'Импорт кошелька', seedPlaceholder: 'вставь свои 24 слова…', importBtn: 'ИМПОРТ',
    badSeed: 'неверная фраза восстановления', wrongPass: 'неверный пароль', unlockTitle: 'Вход в кошелёк',
    receive: 'ПОЛУЧИТЬ', send: 'ОТПРАВИТЬ', scanToPay: 'отправляй только TON на этот адрес',
    sendTitle: 'Отправить TON', recipient: 'адрес получателя', amountTons: 'сумма, TON', comment: 'комментарий (не обязательно)',
    feeNote: 'комиссия сети ≈ 0.01–0.05 TON', sendBtn: 'ОТПРАВИТЬ', badAddr: 'неверный TON-адрес',
    lowBalance: 'недостаточно TON (оставь немного на комиссию)', sent: '✓ отправлено в сеть',
    historyTitle: 'Активность', noHistory: 'транзакций пока нет', in_: 'ПРИХОД', out_: 'РАСХОД',
    settingsTitle: 'НАСТРОЙКИ', showSeed: 'ПОКАЗАТЬ ФРАЗУ ВОССТАНОВЛЕНИЯ', logout: 'ВЫЙТИ',
    wipe: 'удалить кошелёк с устройства? для восстановления нужны 24 слова.',
    jettons: 'Токены', activate: 'отправь ≥ 0.05 TON для активации кошелька',
    balance: 'БАЛАНС', address: 'АДРЕС', yourAddress: 'твой TON-адрес', copy: 'копировать', copied: 'скопировано',
    footer: 'GRID WALLET — некастодиальный кошелёк TON. твои ключи — твоя крипта. Grid Tech не отвечает за утерянные seed-фразы.',
  },
  uz: {
    tabWallet: 'HAMYON', tabActivity: 'FAOLIYAT', tabSettings: 'SOZLAMALAR',
    tagline: 'kalitlaringiz — kriptongiz, TONda',
    createWallet: 'YANGI HAMYON YARATISH', importWallet: 'HAMYONNI IMPORT QILISH',
    setPassword: 'parol o‘ylab toping', unlock: 'OCHISH', password: 'parol',
    passNote: 'parol 24 so‘zli seedni shu qurilmada shifrlaydi. kamida 6 belgi.',
    seedTitle: 'Tiklash iborangi', seedNote: 'bu 24 so‘zni qog‘ozga yozib, oflein saqlang. ibora kimda bo‘lsa, hamyon shunga tegadi. bir marta ko‘rsatiladi.',
    savedIt: 'Iborani yozib oldim', importTitle: 'Hamyonni import qilish', seedPlaceholder: '24 so‘zingizni qo‘ying…', importBtn: 'IMPORT',
    badSeed: 'tiklash iborasi xato', wrongPass: 'parol xato', unlockTitle: 'Hamyonni ochish',
    receive: 'OLISH', send: 'YUBORISH', scanToPay: 'bu manzilga faqat TON yuboring',
    sendTitle: 'TON yuborish', recipient: 'qabul qiluvchi manzili', amountTons: 'summa, TON', comment: 'izoh (ixtiyoriy)',
    feeNote: 'tarmoq komissiyasi ≈ 0.01–0.05 TON', sendBtn: 'YUBORISH', badAddr: 'TON manzili xato',
    lowBalance: 'TON yetmaydi (komissiyaga qoldiring)', sent: '✓ tarmoqqa yuborildi',
    historyTitle: 'Faoliyat', noHistory: 'tranzaksiyalar yo‘q', in_: 'KIRIM', out_: 'CHIQIM',
    settingsTitle: 'SOZLAMALAR', showSeed: 'TIKLASH IBORASINI KO‘RSATISH', logout: 'CHIQISH',
    wipe: 'hamyonni qurilmadan o‘chirish? tiklash uchun 24 so‘z kerak.',
    jettons: 'Tokenlar', activate: 'hamyonni faollashtirish uchun ≥ 0.05 TON yuboring',
    balance: 'BALANS', address: 'MANZIL', yourAddress: 'TON manzilingiz', copy: 'nusxalash', copied: 'nusxalandi',
    footer: 'GRID WALLET — kustodiyasiz TON hamyon. kalitlaringiz — kriptongiz. Grid Tech yo‘qolgan seed uchun javob bermaydi.',
  },
};
const LANGS = ['en', 'ru', 'uz'];
let LANG = localStorage.getItem('gw_lang');
if (!LANGS.includes(LANG)) {
  const tg = window.Telegram && Telegram.WebApp;
  const code = (tg && tg.initDataUnsafe && tg.initDataUnsafe.user && tg.initDataUnsafe.user.language_code) || navigator.language || 'en';
  LANG = code.startsWith('ru') ? 'ru' : code.startsWith('uz') ? 'uz' : 'en';
}
const t = (k) => (I18N[LANG] && I18N[LANG][k] !== undefined ? I18N[LANG][k] : I18N.en[k] ?? k);

// ---------------------------------------------------------------- helpers
const $ = (s) => document.querySelector(s);
const viewEl = $('#view');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function toast(msg, ms = 2400) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove('show'), ms);
}
function copyText(txt) {
  (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject())
    .then(() => toast(t('copied'))).catch(() => toast(txt));
}
const fmtT = (n, dp = 4) => Number(n).toLocaleString('en-US', { maximumFractionDigits: dp });
function ago(ts) {
  const d = Math.max(0, Date.now() - ts) / 1000;
  if (d < 60) return Math.floor(d) + 's';
  if (d < 3600) return Math.floor(d / 60) + 'm';
  if (d < 86400) return Math.floor(d / 3600) + 'h';
  return Math.floor(d / 86400) + 'd';
}
const short = (a) => a ? a.slice(0, 6) + '…' + a.slice(-6) : '';

// ---------------------------------------------------------------- theme/lang
function applyTheme(th) {
  document.documentElement.dataset.theme = th;
  localStorage.setItem('gw_theme', th);
  $('#theme-icon').innerHTML = th === 'light'
    ? '<circle cx="12" cy="12" r="4.5"/><path d="M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9z"/>'
    : '<circle cx="12" cy="12" r="4.5"/><path d="M12 2.5v2.5M12 19v2.5M2.5 12H5M19 12h2.5M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M19.1 4.9l-1.8 1.8M6.7 17.3l-1.8 1.8"/>';
}
(function () {
  let th = localStorage.getItem('gw_theme');
  if (th !== 'light' && th !== 'dark') {
    const tg = window.Telegram && Telegram.WebApp;
    th = tg && tg.colorScheme ? tg.colorScheme : (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  }
  applyTheme(th);
})();
function applyLang() {
  $('#lang-btn').textContent = LANG.toUpperCase();
  $('#footnote').textContent = t('footer');
  document.querySelectorAll('.tab[data-i18n]').forEach((el) => {
    const label = el.querySelector('span');
    if (label) label.textContent = t(el.dataset.i18n);
  });
  document.documentElement.lang = LANG;
}

// ---------------------------------------------------------------- wallet core
const KEYS = 'gw_keys';
const loadKeys = () => { try { return JSON.parse(localStorage.getItem(KEYS)); } catch { return null; } };
const saveKeys = (k) => localStorage.setItem(KEYS, JSON.stringify(k));
const wipeKeys = () => localStorage.removeItem(KEYS);
const SESSION = { mnemonic: null };

const client = new TonClient({
  endpoint: 'https://toncenter.com/api/v2/jsonRPC',
  apiKey: window.__TONCENTER_KEY__ || undefined,
});

async function walletFromMnemonic(words) {
  const kp = await mnemonicToPrivateKey(words);
  const contract = WalletContractV4.create({ workchain: 0, publicKey: kp.publicKey });
  return { kp, contract, address: contract.address.toString({ urlSafe: true, bounceable: false }) };
}

// PBKDF2 + AES-GCM envelope for the seed
const b64 = {
  enc: (b) => btoa(String.fromCharCode(...new Uint8Array(b))),
  dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};
async function deriveKey(password, salt) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 210000, hash: 'SHA-256' }, km,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptSeed(words, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(words.join(' ')));
  return { salt: b64.enc(salt), iv: b64.enc(iv), data: b64.enc(data) };
}
async function decryptSeed(enc, password) {
  const key = await deriveKey(password, b64.dec(enc.salt));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(enc.iv) }, key, b64.dec(enc.data));
  return new TextDecoder().decode(pt).split(' ');
}

// ---------------------------------------------------------------- TON network
const toncenter = async (method, params) => {
  const r = await fetch(`https://toncenter.com/api/v2/${method}?` + new URLSearchParams(params));
  const j = await r.json();
  if (!j.ok) throw new Error(j.error || 'toncenter error');
  return j.result;
};

async function fetchState(addr) {
  const info = await toncenter('getAddressInformation', { address: addr });
  return {
    balance: fromNano(info.balance || '0'),
    active: info.state === 'active' || Number(info.balance) > 0,
  };
}

async function fetchPrice() {
  try {
    const r = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=the-open-network&vs_currencies=usd');
    const j = await r.json();
    return j['the-open-network'].usd;
  } catch { return 0; }
}

async function fetchJettons(addr) {
  try {
    const r = await fetch(`https://tonapi.io/v2/accounts/${addr}/jettons?currencies=usd`);
    const j = await r.json();
    return (j.balances || [])
      .filter((b) => Number(b.balance) > 0)
      .map((b) => ({
        symbol: b.jetton.symbol || '?',
        name: b.jetton.name || '',
        image: b.jetton.image || '',
        amount: Number(b.balance) / 10 ** (b.jetton.decimals || 9),
        usd: b.price * (Number(b.balance) / 10 ** (b.jetton.decimals || 9)),
      }))
      .sort((a, b2) => (b2.usd || 0) - (a.usd || 0))
      .slice(0, 10);
  } catch { return []; }
}

async function fetchHistory(addr) {
  const txs = await toncenter('getTransactions', { address: addr, limit: 20 });
  const out = [];
  for (const tx of txs) {
    const im = tx.in_msg || {};
    if (im.source && Number(im.value) > 0) {
      out.push({
        dir: 'in', amount: fromNano(im.value),
        addr: im.source.address || '', fee: fromNano(tx.fee || 0),
        comment: im.message || '', time: (tx.utime || 0) * 1000,
      });
    }
    for (const om of tx.out_msgs || []) {
      if (om.destination) {
        out.push({
          dir: 'out', amount: fromNano(om.value),
          addr: om.destination, fee: fromNano(tx.fee || 0),
          comment: om.message || '', time: (tx.utime || 0) * 1000,
        });
      }
    }
  }
  return out.slice(0, 25);
}

async function sendTON(mnemonic, toAddr, tons, comment) {
  const { kp, contract } = await walletFromMnemonic(mnemonic);
  const opened = client.open(contract);
  const seqno = await opened.getSeqno();
  const friendly = Address.parseFriendly(toAddr.trim());
  await opened.sendTransfer({
    seqno,
    secretKey: kp.secretKey,
    sendMode: 3, // pay gas separately + ignore errors
    messages: [internal({
      to: friendly.isBounceable ? friendly.address : new Address(friendly.address.workChain, friendly.address.hash),
      bounce: friendly.isBounceable,
      value: toNano(tons),
      body: comment ? comment : undefined,
    })],
  });
  return seqno;
}

// ---------------------------------------------------------------- router
let pollTimer = null;
const stopPoll = () => { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } };
const poll = (fn, ms = 7000) => { stopPoll(); pollTimer = setInterval(fn, ms); };
const typing = () => document.activeElement && viewEl.contains(document.activeElement);

function setActiveTab(route) {
  document.querySelectorAll('.tab').forEach((el) => el.classList.toggle('active', el.dataset.route === route));
}

async function route() {
  stopPoll();
  const keys = loadKeys();
  const page = (location.hash || '#/wallet').slice(2).split('/').filter(Boolean)[0] || 'wallet';
  setActiveTab('/' + page);
  try {
    if (!keys) return renderWelcome();
    if (!SESSION.mnemonic) return renderUnlock(keys);
    if (page === 'wallet') return await renderWallet();
    if (page === 'activity') return await renderActivity();
    if (page === 'settings') return await renderSettings();
    location.hash = '#/wallet';
  } catch (e) {
    viewEl.innerHTML = `<div class="narrow"><div class="empty">${esc(e.message || 'error')}</div></div>`;
  }
}
window.addEventListener('hashchange', route);

// ---------------------------------------------------------------- onboarding
function renderWelcome() {
  setActiveTab('');
  viewEl.innerHTML = `
    <div class="onboard">
      <div class="ob-logo"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div>
      <h1 class="ob-title">GRID&nbsp;WALLET</h1>
      <p class="ob-tag">${t('tagline')}</p>
      <div class="panel ob-panel">
        <button class="btn" id="w-new">${t('createWallet')}</button>
        <div style="height:10px"></div>
        <button class="btn ghost" id="w-imp">${t('importWallet')}</button>
      </div>
    </div>`;
  $('#w-new').onclick = async () => {
    const words = await mnemonicNew();
    renderSetPassword(words, false);
  };
  $('#w-imp').onclick = () => renderImport();
}

function renderSetPassword(words, isImport) {
  setActiveTab('');
  viewEl.innerHTML = `
    <div class="narrow">
      <div class="panel">
        <h3>${t('setPassword').toUpperCase()}</h3>
        <p class="note">${t('passNote')}</p>
        <div style="height:12px"></div>
        <div class="field"><label>${t('password')}</label><input id="p1" type="password" placeholder="••••••"></div>
        <div class="field"><label>${t('password')} 2</label><input id="p2" type="password" placeholder="••••••"></div>
        <button class="btn" id="p-go">→</button>
      </div>
    </div>`;
  $('#p-go').onclick = async () => {
    const p1 = $('#p1').value, p2 = $('#p2').value;
    if (p1.length < 6 || p1 !== p2) return toast(t('wrongPass'));
    if (!isImport) return renderBackup(words, p1);
    const enc = await encryptSeed(words, p1);
    const { address } = await walletFromMnemonic(words);
    saveKeys({ address, enc, created: Date.now() });
    SESSION.mnemonic = words;
    location.hash = '#/wallet';
    route();
  };
}

async function renderBackup(words, password) {
  setActiveTab('');
  viewEl.innerHTML = `
    <div class="narrow">
      <div class="panel">
        <h3>${esc(t('seedTitle'))}</h3>
        <p class="note warn">${t('seedNote')}</p>
        <div class="seed-grid">
          ${words.map((w, i) => `<div class="seed-cell"><span class="n">${i + 1}</span><span class="w">${esc(w)}</span></div>`).join('')}
        </div>
        <button class="btn" id="s-done">${t('savedIt')}</button>
      </div>
    </div>`;
  $('#s-done').onclick = async () => {
    const enc = await encryptSeed(words, password);
    const { address } = await walletFromMnemonic(words);
    saveKeys({ address, enc, created: Date.now() });
    SESSION.mnemonic = words;
    location.hash = '#/wallet';
    route();
  };
}

function renderImport() {
  setActiveTab('');
  viewEl.innerHTML = `
    <div class="narrow">
      <div class="panel">
        <h3>${esc(t('importTitle')).toUpperCase()}</h3>
        <div class="field"><label>${t('seedTitle')}</label>
          <textarea id="i-seed" rows="4" placeholder="${esc(t('seedPlaceholder'))}"></textarea></div>
        <button class="btn" id="i-go">${t('importBtn')}</button>
      </div>
    </div>`;
  $('#i-go').onclick = async () => {
    const words = $('#i-seed').value.trim().toLowerCase().split(/[\s,]+/).filter(Boolean);
    if (!(await mnemonicValidate(words))) return toast(t('badSeed'));
    renderSetPassword(words, true);
  };
}

function renderUnlock(keys) {
  setActiveTab('');
  viewEl.innerHTML = `
    <div class="narrow">
      <div class="panel">
        <h3>${esc(t('unlockTitle')).toUpperCase()}</h3>
        <div class="addr-box" style="margin-bottom:4px"><div class="k">${t('address')}</div>
          <span class="mono">${esc(keys.address)}</span></div>
        <div class="field"><label>${t('password')}</label><input id="u-pass" type="password" placeholder="••••••"></div>
        <button class="btn" id="u-go">${t('unlock')}</button>
      </div>
    </div>`;
  const go = async () => {
    try {
      SESSION.mnemonic = await decryptSeed(keys.enc, $('#u-pass').value);
      route();
    } catch { toast(t('wrongPass')); }
  };
  $('#u-go').onclick = go;
  $('#u-pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
}

// ---------------------------------------------------------------- wallet view
async function renderWallet() {
  const keys = loadKeys();
  const addr = keys.address;
  viewEl.innerHTML = `<div class="loading">…</div>`;
  const [state, price] = await Promise.all([fetchState(addr), fetchPrice()]);
  const usd = state.balance * price;

  viewEl.innerHTML = `
    <div class="narrow">
      <div class="pay-card">
        <div class="pc-top">
          <span class="pc-brand"><span class="mini-grid"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></span>TON</span>
          <span class="pc-mode">GRID WALLET</span>
        </div>
        <div class="pc-bal mono">${fmtT(state.balance)}</div>
        <div class="pc-unit">TONCOIN</div>
        ${price > 0 ? `<div class="pc-equiv"><span>≈ <b class="mono">$${fmtT(usd, 2)}</b></span></div>` : ''}
        <div class="pc-bottom">
          <button class="pc-addr mono" id="pc-copy" title="${t('copy')}">${short(addr)} ⧉</button>
          <span class="pc-net"><span class="live-dot"></span>TON MAINNET</span>
        </div>
      </div>
      ${!state.active && state.balance === '0' ? `<p class="note warn" style="margin:-6px 2px 12px">${t('activate')}</p>` : ''}
      <div class="quick2">
        <button class="btn" id="w-receive">▽ ${t('receive')}</button>
        <button class="btn ghost" id="w-send">▲ ${t('send')}</button>
      </div>
      <div class="panel" id="receive-panel" style="display:none;text-align:center">
        <h3>${t('receive')}</h3>
        <img src="https://api.qrserver.com/v1/create-qr-code/?size=170x170&data=${esc('ton://transfer/' + addr)}" alt="QR"
             style="border-radius:12px;background:#fff;padding:8px;width:170px;height:170px">
        <div class="addr-box" style="margin:12px 0 0;text-align:left">
          <div class="k">${t('yourAddress')}</div><span class="mono">${esc(addr)}</span></div>
        <p class="note">${t('scanToPay')}</p>
      </div>
      <div class="panel" id="send-panel" style="display:none">
        <h3>${t('sendTitle')}</h3>
        <div class="field"><label>${t('recipient')}</label><input id="s-to" class="mono" placeholder="UQ… / EQ… / 0:…"></div>
        <div class="field"><label>${t('amountTons')}</label><input id="s-amt" type="number" min="0" step="any" placeholder="0.1"></div>
        <div class="field"><label>${t('comment')}</label><input id="s-cm" maxlength="120"></div>
        <button class="btn" id="s-go">${t('sendBtn')}</button>
        <p class="note">${t('feeNote')}</p>
      </div>
      <div id="jets"></div>
    </div>`;

  $('#pc-copy').onclick = () => copyText(addr);
  $('#w-receive').onclick = () => {
    const p = $('#receive-panel');
    p.style.display = p.style.display === 'none' ? 'block' : 'none';
  };
  $('#w-send').onclick = () => {
    const p = $('#send-panel');
    p.style.display = p.style.display === 'none' ? 'block' : 'none';
  };
  $('#s-go').onclick = async () => {
    const to = $('#s-to').value.trim();
    const amt = Number($('#s-amt').value);
    const cm = $('#s-cm').value.trim();
    let okAddr = true;
    try { Address.parseFriendly(to); } catch { okAddr = false; }
    if (!okAddr) return toast(t('badAddr'));
    if (!(amt > 0)) return toast(t('amountTons'));
    if (amt + 0.01 > Number(state.balance)) return toast(t('lowBalance'));
    $('#s-go').disabled = true;
    try {
      await sendTON(SESSION.mnemonic, to, $('#s-amt').value.trim(), cm);
      toast(t('sent'));
      $('#s-to').value = ''; $('#s-amt').value = ''; $('#s-cm').value = '';
      $('#send-panel').style.display = 'none';
      setTimeout(() => route(), 1500);
    } catch (e) {
      toast((e && e.message) || 'send failed');
    } finally { $('#s-go').disabled = false; }
  };

  fetchJettons(addr).then((jets) => {
    if (!jets.length || !document.getElementById('jets')) return;
    document.getElementById('jets').innerHTML = `
      <div class="sec-title">${t('jettons')}</div>
      <div class="chip-row">${jets.map((j) => `
        <span class="chip">
          ${j.image ? `<img src="${esc(j.image)}" alt="">` : ''}
          <span><b>${esc(j.symbol)}</b><br><span class="mono">${fmtT(j.amount, 2)}</span></span>
        </span>`).join('')}</div>`;
  });

  poll(async () => { if (!typing()) route(); }, 12000);
}

// ---------------------------------------------------------------- activity
async function renderActivity() {
  const addr = loadKeys().address;
  viewEl.innerHTML = `<div class="loading">…</div>`;
  const list = await fetchHistory(addr).catch(() => []);
  viewEl.innerHTML = `
    <div class="narrow">
      <div class="sec-title">${t('historyTitle')}</div>
      <div class="feed">${list.map((h) => `
        <div class="row">
          <span class="s">
            <span class="side-tag ${h.dir === 'in' ? 'buy' : 'sell'}">${h.dir === 'in' ? esc(t('in_')) : esc(t('out_'))}</span>
            <span class="mono ${h.dir === 'in' ? 'amount-pos' : 'amount-neg'}">${h.dir === 'in' ? '+' : '−'}${fmtT(h.amount)}</span> TON
            <span style="color:var(--dim)">· ${esc(short(h.addr))}${h.comment ? ' · ' + esc(h.comment.slice(0, 20)) : ''}</span>
          </span>
          <span class="m">${ago(h.time)}</span>
        </div>`).join('') || `<div class="row"><span class="s">${t('noHistory')}</span></div>`}
      </div>
    </div>`;
  poll(async () => { if (!typing()) route(); }, 15000);
}

// ---------------------------------------------------------------- settings
async function renderSettings() {
  const keys = loadKeys();
  viewEl.innerHTML = `
    <div class="narrow">
      <div class="sec-title">${t('settingsTitle')}</div>
      <div class="addr-box"><div class="k">${t('yourAddress')}</div>
        <span class="mono">${esc(keys.address)}</span>
        <button class="btn ghost" style="width:auto;padding:4px 12px;margin-top:10px;font-size:11px" id="st-copy">${t('copy')}</button>
      </div>
      <button class="btn ghost" id="st-seed" style="margin-bottom:10px">🔑 ${t('showSeed')}</button>
      <div class="panel" id="seed-box" style="display:none">
        <p class="note warn" style="margin:0 0 6px">${t('seedNote')}</p>
        <div class="seed-grid">
          ${SESSION.mnemonic.map((w, i) => `<div class="seed-cell"><span class="n">${i + 1}</span><span class="w">${esc(w)}</span></div>`).join('')}
        </div>
      </div>
      <button class="btn ghost" id="st-logout" style="border-color:rgba(255,82,82,.4);color:#ff5252">${t('logout')}</button>
    </div>`;
  $('#st-copy').onclick = () => copyText(keys.address);
  $('#st-seed').onclick = () => {
    const p = $('#seed-box');
    p.style.display = p.style.display === 'none' ? 'block' : 'none';
  };
  $('#st-logout').onclick = () => {
    if (!confirm(t('wipe'))) return;
    wipeKeys();
    SESSION.mnemonic = null;
    location.hash = '#/wallet';
    route();
  };
}

// ---------------------------------------------------------------- boot
(function () {
  const tg = window.Telegram && window.Telegram.WebApp;
  if (tg) { tg.ready(); tg.expand(); try { tg.setBackgroundColor('#000000'); tg.setHeaderColor('#000000'); } catch {} }
  applyLang();
  $('#lang-btn').onclick = () => {
    LANG = LANGS[(LANGS.indexOf(LANG) + 1) % LANGS.length];
    localStorage.setItem('gw_lang', LANG);
    applyLang();
    route();
  };
  $('#theme-btn').onclick = () => {
    applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
    route();
  };
  route();
})();
