'use strict';
/* InnerSite 解密 + 導覽。前端不含任何明文知識；只含 shell + 解密邏輯。
   加密參數須與 script/_crypto_envelope.py 一致：
   PBKDF2-SHA256・iterations(META.iterations)・salt(META.salt_b64)・AES-GCM 256・iv 12B・tag 128bit・aad=UTF-8。 */
const META = window.__META__;
let KEY = null;        // 快取的 CryptoKey（導一次重用）
let MANIFEST = null;   // 解密後的主題清單

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

async function unlock(){
  const pw = $('pw').value;
  if(!pw){ setErr('請輸入密碼', false); return; }
  setErr('解鎖中…（導出金鑰需數秒）', true);
  $('unlock').disabled = true;
  try {
    KEY = await deriveKey(pw);                                  // 慢，但只一次
    const env = await fetchJson('data/manifest.enc.json');
    MANIFEST = JSON.parse(await decryptEnv(env, 'manifest'));   // 錯密碼 → throw（GCM InvalidTag）
    $('gate').hidden = true; $('app').hidden = false;
    renderTopicList();
    route();                                                    // 若網址帶 #slug 直接開該頁
  } catch(e){
    KEY = null; MANIFEST = null;
    setErr('密碼錯誤或資料載入失敗，請重試', false);
    $('unlock').disabled = false;
  }
}
function setErr(msg, busy){
  const el = $('err'); el.textContent = msg;
  el.classList.toggle('busy', !!busy);
}

function renderTopicList(){
  $('page').hidden = true; $('page').innerHTML = '';
  $('topiclist').hidden = false;
  $('topiclist').innerHTML = MANIFEST.topics.map(t => {
    const c = t.counts || {};
    const sup = t.is_full_page ? '' : '<span class="sup">補充</span>';
    return `<a class="t" href="#${encodeURIComponent(t.slug)}">`+   // 點擊走 hashchange→route，不依賴 data-slug
      `${sup}<span class="tn">${esc(t.name)}</span>`+               // manifest 雖經 GCM 認證，display 仍 escape 防殘留 XSS
      `<span class="tc">內 ${c.inad_im||0}・外 ${c.inad_surgery||0}・通 ${c.common||0}・合計 ${c.total||0}</span></a>`;
  }).join('');
}

async function openTopic(slug){
  const meta = MANIFEST.topics.find(t => t.slug === slug);
  if(!meta){ renderTopicList(); return; }
  try {
    const env = await fetchJson(`data/topics/${slug}.enc.json`);
    const payload = JSON.parse(await decryptEnv(env, slug));    // {name, html}
    $('topiclist').hidden = true;
    $('page').hidden = false;
    $('page').innerHTML = `<button id="back">← 主題清單</button>`+
      `<article class="kpage">${payload.html}</article>`;        // html 為 0009 信任產物（已 Python 端 escape）
    $('back').onclick = () => { location.hash = ''; renderTopicList(); };
    window.scrollTo(0, 0);
  } catch(e){
    $('page').hidden = false; $('topiclist').hidden = true;
    $('page').innerHTML = `<button id="back">← 主題清單</button><p class="note">此主題載入失敗。</p>`;
    $('back').onclick = () => { location.hash = ''; renderTopicList(); };
  }
}

function route(){
  const s = decodeURIComponent(location.hash.replace(/^#/, ''));
  if(KEY && s) openTopic(s);
  else if(KEY) renderTopicList();
}

$('unlock').onclick = unlock;
$('pw').addEventListener('keydown', e => { if(e.key === 'Enter') unlock(); });
window.addEventListener('hashchange', route);
