'use strict';
/* InnerSite 解密 + 導覽。前端不含任何明文知識；只含 shell + 解密邏輯。
   加密參數須與 script/_crypto_envelope.py 一致：
   PBKDF2-SHA256・iterations(META.iterations)・salt(META.salt_b64)・AES-GCM 256・iv 12B・tag 128bit・aad=UTF-8。

   導覽守衛（user 2026-06-14）：密碼頁 → 目錄頁 → 分頁；金鑰只存記憶體、不持久化。
   - 目錄頁僅在解鎖（KEY+MANIFEST 在記憶體）後存在。
   - 分頁只容許從目錄頁點入（VIEW==='catalog' 時才能開）；分頁可按「返回目錄」回目錄頁。
   - 不使用 hash deep-link；reload 或任何非法路徑 → KEY 消失 → 一律回密碼頁。 */
const META = window.__META__;
let KEY = null;        // 快取的 CryptoKey（導一次重用；reload 即消失）
let MANIFEST = null;   // 解密後的主題清單 + 歷年題數 stats
let VIEW = 'gate';     // 'gate' | 'catalog' | 'topic'

const $ = id => document.getElementById(id);
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const enc = s => new TextEncoder().encode(s);
const esc = s => String(s == null ? '' : s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
  .replace(/"/g,'&quot;').replace(/'/g,'&#39;');

async function deriveKey(password){
  const baseKey = await crypto.subtle.importKey(
    'raw', enc(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt:b64(META.salt_b64), iterations:META.iterations, hash:'SHA-256'},
    baseKey, {name:'AES-GCM', length:256}, false, ['decrypt']);
}
async function decryptEnv(env, aad){
  const pt = await crypto.subtle.decrypt(
    {name:'AES-GCM', iv:b64(env.iv_b64), additionalData:enc(aad)},
    KEY, b64(env.ct_b64));
  return new TextDecoder().decode(pt);
}
async function fetchJson(path){
  const r = await fetch(path, {cache:'no-store'});
  if(!r.ok) throw new Error('fetch ' + path + ' → ' + r.status);
  return r.json();
}

function setErr(msg, busy){
  const el = $('err'); el.textContent = msg;
  el.classList.toggle('busy', !!busy);
}

/* ── 導覽守衛 ─────────────────────────────────────────── */
function toGate(){
  VIEW = 'gate'; KEY = null; MANIFEST = null;
  $('app').hidden = true; $('gate').hidden = false;
  $('pw').value = '';
}
function showCatalog(){
  if(!KEY || !MANIFEST){ toGate(); return; }   // 目錄頁只在解鎖後存在
  VIEW = 'catalog';
  $('gate').hidden = true; $('app').hidden = false;
  $('page').hidden = true; $('page').innerHTML = '';
  $('catalog').hidden = false;
  window.scrollTo(0, 0);
}

async function unlock(){
  const pw = $('pw').value;
  if(!pw){ setErr('請輸入密碼', false); return; }
  setErr('解鎖中…（導出金鑰需數秒）', true);
  $('unlock').disabled = true;
  try {
    KEY = await deriveKey(pw);                                  // 慢，但只一次
    const env = await fetchJson('data/manifest.enc.json');
    MANIFEST = JSON.parse(await decryptEnv(env, 'manifest'));   // 錯密碼 → throw（GCM InvalidTag）
    renderCatalog();
    setErr('', false);
    showCatalog();                                             // 解鎖後一律進目錄頁
  } catch(e){
    toGate();                                                 // 失敗一律回密碼頁（fail-closed）
    setErr('密碼錯誤或資料載入失敗，請重試', false);
  } finally {
    $('unlock').disabled = false;
  }
}

/* ── 目錄頁：歷年題數 + 主題清單（manifest 已排序）─────────── */
function renderStats(){
  const s = MANIFEST.stats;
  if(!s || !Array.isArray(s.years)){ $('statspanel').hidden = true; return; }
  const cats = [['inad_im','內科'], ['inad_surgery','外科'], ['common','通論']];
  let head = '<tr><th>年度</th>' + cats.map(c => `<th>${esc(c[1])}</th>`).join('') + '<th>小計</th></tr>';
  let rows = s.years.map(y => {
    const d = (s.by_year && s.by_year[String(y)]) || {};
    return `<tr><td class="yr">${esc(y)}</td>` +
      cats.map(c => `<td>${esc(d[c[0]] || 0)}</td>`).join('') +
      `<td class="tot">${esc(d.total || 0)}</td></tr>`;
  }).join('');
  const ct = s.cat_totals || {};
  let total = `<tr class="total"><td class="yr">合計</td>` +
    cats.map(c => `<td>${esc(ct[c[0]] || 0)}</td>`).join('') +
    `<td class="tot">${esc(s.total || 0)}</td></tr>`;
  $('stab').innerHTML = head + rows + total;
  $('statspanel').hidden = false;
}

function renderCatalog(){
  renderStats();
  $('topiclist').innerHTML = MANIFEST.topics.map(t => {
    const c = t.counts || {};
    const sup = t.is_full_page ? '' : '<span class="sup">補充</span>';
    return `<button type="button" class="t" data-slug="${esc(t.slug)}">` +   // 點擊走守衛化的 openTopic
      `${sup}<span class="tn">${esc(t.name)}</span>` +                       // manifest 雖經 GCM 認證，display 仍 escape 防殘留 XSS
      `<span class="tc">內 ${esc(c.inad_im || 0)}・外 ${esc(c.inad_surgery || 0)}・` +
      `通 ${esc(c.common || 0)}・合計 ${esc(c.total || 0)}</span></button>`;
  }).join('');
}

/* ── 分頁：只容許從目錄頁進入 ─────────────────────────── */
async function openTopic(slug){
  if(!KEY || !MANIFEST || VIEW !== 'catalog'){ toGate(); return; }   // 非「目錄頁點入」一律回密碼頁
  const meta = MANIFEST.topics.find(t => t.slug === slug);
  if(!meta){ return; }
  try {
    const env = await fetchJson(`data/topics/${encodeURIComponent(slug)}.enc.json`);
    const payload = JSON.parse(await decryptEnv(env, slug));    // {name, html}
    VIEW = 'topic';
    $('catalog').hidden = true;
    $('page').hidden = false;
    $('page').innerHTML = `<button id="back" type="button">← 返回目錄</button>` +
      `<article class="kpage">${payload.html}</article>`;        // html 為 0009 信任產物（已 Python 端 escape）
    $('back').onclick = showCatalog;
    window.scrollTo(0, 0);
  } catch(e){
    VIEW = 'topic';
    $('catalog').hidden = true; $('page').hidden = false;
    $('page').innerHTML = `<button id="back" type="button">← 返回目錄</button><p class="note">此主題載入失敗。</p>`;
    $('back').onclick = showCatalog;
  }
}

/* ── 事件綁定 ─────────────────────────────────────────── */
$('unlock').onclick = unlock;
$('pw').addEventListener('keydown', e => { if(e.key === 'Enter') unlock(); });
$('pwtoggle').onclick = () => {
  const pw = $('pw'), btn = $('pwtoggle');
  const show = pw.type === 'password';
  pw.type = show ? 'text' : 'password';
  btn.textContent = show ? '隱藏' : '顯示';
  btn.setAttribute('aria-pressed', show ? 'true' : 'false');
  pw.focus();
};
$('topiclist').addEventListener('click', e => {
  const btn = e.target.closest('.t');
  if(btn && btn.dataset.slug) openTopic(btn.dataset.slug);
});
// 清掉任何 hash deep-link（不提供 hash 導覽）；初始一律密碼頁
if(location.hash){ history.replaceState(null, '', location.pathname + location.search); }
toGate();
