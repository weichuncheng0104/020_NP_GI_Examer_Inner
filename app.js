'use strict';
/* InnerSite 解密 + 導覽。前端不含任何明文知識；只含 shell + 解密邏輯。
   加密參數須與 script/_crypto_envelope.py 一致：
   PBKDF2-SHA256・iterations(META.iterations)・salt(META.salt_b64)・AES-GCM 256・iv 12B・tag 128bit・aad=UTF-8。

   導覽守衛 + 驗證 band（user 2026-06-14）：頂部 band 顯示驗證狀態，金鑰只存記憶體、不持久化。
   - band「已驗證」狀態 = KEY+MANIFEST 是否在記憶體（非獨立開關）；解鎖後 band 自動收合，可手動展開（內含鎖定鈕）。
   - 目錄/分頁內容僅在解鎖後存在；分頁只容許從目錄頁點入（VIEW==='catalog'）。
   - 不使用 hash deep-link；reload / 解密失敗 / 按鎖定 → KEY 消失 → band 回未驗證、內容收起（fail-closed）。 */
const META = window.__META__;
let KEY = null;        // 快取的 CryptoKey（導一次重用；reload 即消失）
let MANIFEST = null;   // 解密後的主題清單 + 歷年題數 stats
let VIEW = 'gate';     // 'gate' | 'catalog' | 'topic'
let BAND_OPEN = false; // 已驗證後頂部 band 是否展開（預設收合；未驗證時恆展開）

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

/* ── 導覽守衛 + 驗證 band ──────────────────────────────
   band 的「已驗證/未驗證」一律由 KEY+MANIFEST 是否存在決定（非獨立開關）；
   金鑰消失（reload/解密失敗/按鎖定）→ band 自動回未驗證、內容收起。
   「收合」純屬視覺：內容永遠由解密 gate，收合 band 不會讓任何明文提早出現。 */
function renderBand(){
  const authed = !!(KEY && MANIFEST);
  $('bstat').textContent = authed ? '✓ 已驗證' : '🔒 未驗證';
  $('bstat').className = 'bstat ' + (authed ? 'ok' : 'no');
  $('authpanel').hidden = authed;       // 未驗證才顯示密碼表單
  $('lockpanel').hidden = !authed;      // 已驗證才顯示鎖定區
  $('btoggle').hidden = !authed;        // 只有已驗證才能收合/展開
  const open = authed ? BAND_OPEN : true;   // 未驗證一律展開（要能輸入密碼）
  $('bandbody').hidden = !open;
  $('btoggle').textContent = open ? '收合' : '展開';
  $('btoggle').setAttribute('aria-expanded', open ? 'true' : 'false');
}

function toGate(){
  VIEW = 'gate'; KEY = null; MANIFEST = null; BAND_OPEN = false;
  $('app').hidden = true;                       // 內容（目錄/分頁）一律收起
  $('page').hidden = true; $('page').innerHTML = '';
  $('catalog').hidden = false;
  $('pw').value = '';
  renderBand();                                 // band 回未驗證 + 密碼表單展開
}
function showCatalog(){
  if(!KEY || !MANIFEST){ toGate(); return; }    // 目錄頁只在解鎖後存在
  VIEW = 'catalog';
  $('app').hidden = false;
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
    BAND_OPEN = false;                                          // 解鎖後 band 自動收合
    renderBand();                                              // 切到「✓ 已驗證」
    showCatalog();                                             // 解鎖後一律進目錄頁
  } catch(e){
    toGate();                                                 // 失敗一律回未驗證（fail-closed）
    setErr('密碼錯誤或資料載入失敗，請重試', false);
    $('pw').focus();
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
$('lock').onclick = () => { toGate(); $('pw').focus(); };   // 鎖定：清金鑰、回未驗證、收起內容
$('btoggle').onclick = () => {                              // 收合/展開（僅已驗證有效）
  if(!(KEY && MANIFEST)) return;
  BAND_OPEN = !BAND_OPEN;
  renderBand();
};
$('topiclist').addEventListener('click', e => {
  const btn = e.target.closest('.t');
  if(btn && btn.dataset.slug) openTopic(btn.dataset.slug);
});
// 清掉任何 hash deep-link（不提供 hash 導覽）；初始一律密碼頁
if(location.hash){ history.replaceState(null, '', location.pathname + location.search); }
toGate();
