/* ══════════════════════════════════════════════════
   auth.js — INOTI 공통 인증 모듈 v3
   - file:// / HTTPS 환경 모두 정상 동작
   - SHA-256 해시 기반 (평문 비밀번호 소스 미노출)
   - 비밀번호 변경 시: sha256 해시값만 교체
     https://emn178.github.io/online-tools/sha256.html
   사용법:
     루트 페이지     : <script src="auth.js"></script>
     1단계 하위      : <script src="../auth.js"></script>
     2단계 하위      : <script src="../../auth.js"></script>
══════════════════════════════════════════════════ */

const INOTI_AUTH = {
  ACCESS_HASH: "66c369b0cff427366ec11f44134f8375a842f3b8ea177a23c11ecf144ce2a099",
  ADMIN_HASH:  "1ba2d150fff97394cf2d770411b0151f526341f07a05999cff312ab5c489559f",
  SESSION_KEY: "inoti_access",
  ADMIN_KEY:   "inoti_admin",
  SESSION_MIN: 1440,

  /* ── SHA-256: crypto.subtle 우선, file:// 환경은 순수 JS 폴백 ── */
  async _sha256(str) {
    if (window.crypto && window.crypto.subtle) {
      try {
        const buf = await window.crypto.subtle.digest(
          "SHA-256", new TextEncoder().encode(str)
        );
        return Array.from(new Uint8Array(buf))
          .map(b => b.toString(16).padStart(2, "0")).join("");
      } catch(e) { /* 보안 컨텍스트 오류 → 폴백 */ }
    }
    return _sha256Pure(str);
  },

  isLoggedIn() {
    const t = localStorage.getItem(this.SESSION_KEY);
    return t && (Date.now() - parseInt(t)) / 60000 < this.SESSION_MIN;
  },
  isAdmin() {
    const t = localStorage.getItem(this.ADMIN_KEY);
    return t && (Date.now() - parseInt(t)) / 60000 < 60;
  },
  login()      { localStorage.setItem(this.SESSION_KEY, Date.now()); },
  adminLogin() { localStorage.setItem(this.ADMIN_KEY,   Date.now()); },
  adminLogout(){ localStorage.removeItem(this.ADMIN_KEY); },
  logout() {
    localStorage.removeItem(this.SESSION_KEY);
    localStorage.removeItem(this.ADMIN_KEY);
  }
};

/* ── 순수 JS SHA-256 (file:// 환경 폴백) ──────────────────────── */
function _sha256Pure(msg) {
  function rr(v, a) { return (v >>> a) | (v << (32 - a)); }
  function add(...args) {
    return args.reduce((s, n) => (s + n) >>> 0);
  }
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  let h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];

  /* UTF-8 인코딩 */
  const bytes = [];
  for (let i = 0; i < msg.length; i++) {
    let c = msg.charCodeAt(i);
    if (c < 0x80) { bytes.push(c); }
    else if (c < 0x800) { bytes.push(0xc0|(c>>6), 0x80|(c&0x3f)); }
    else { bytes.push(0xe0|(c>>12), 0x80|((c>>6)&0x3f), 0x80|(c&0x3f)); }
  }
  const len = bytes.length;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  const bitLen = len * 8;
  bytes.push(0,0,0,0,
    (bitLen/0x1000000)&0xff,(bitLen/0x10000)&0xff,(bitLen/0x100)&0xff,bitLen&0xff);

  for (let i = 0; i < bytes.length; i += 64) {
    const w = [];
    for (let j = 0; j < 16; j++)
      w[j] = (bytes[i+j*4]<<24)|(bytes[i+j*4+1]<<16)|(bytes[i+j*4+2]<<8)|bytes[i+j*4+3];
    for (let j = 16; j < 64; j++) {
      const s0 = rr(w[j-15],7)^rr(w[j-15],18)^(w[j-15]>>>3);
      const s1 = rr(w[j-2],17)^rr(w[j-2],19)^(w[j-2]>>>10);
      w[j] = add(w[j-16], s0, w[j-7], s1);
    }
    let [a,b,c,d,e,f,g,hh] = h;
    for (let j = 0; j < 64; j++) {
      const S1  = rr(e,6)^rr(e,11)^rr(e,25);
      const ch  = (e&f)^(~e&g);
      const t1  = add(hh, S1, ch, K[j], w[j]);
      const S0  = rr(a,2)^rr(a,13)^rr(a,22);
      const maj = (a&b)^(a&c)^(b&c);
      const t2  = add(S0, maj);
      hh=g; g=f; f=e; e=add(d,t1);
      d=c; c=b; b=a; a=add(t1,t2);
    }
    h = h.map((v,i) => add(v,[a,b,c,d,e,f,g,hh][i]));
  }
  return h.map(v => v.toString(16).padStart(8,"0")).join("");
}

/* ── 공통 잠금 화면 스타일 ── */
function _injectAuthStyle() {
  if (document.getElementById("_inoti_auth_style")) return;
  const s = document.createElement("style");
  s.id = "_inoti_auth_style";
  s.textContent = `
.auth-ov{position:fixed;inset:0;background:linear-gradient(135deg,#060d1a 0%,#0d1b2e 100%);display:flex;align-items:center;justify-content:center;z-index:99999;font-family:'Noto Sans KR','Apple SD Gothic Neo',sans-serif;}
.auth-bx{background:rgba(13,27,46,0.97);border:1px solid rgba(255,255,255,0.1);border-radius:20px;padding:40px 36px;width:340px;max-width:90vw;text-align:center;box-shadow:0 24px 80px rgba(0,0,0,0.6);animation:authIn .4s ease;}
@keyframes authIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
.auth-logo{font-size:28px;font-weight:900;color:#e8f0fb;margin-bottom:6px;letter-spacing:2px;}
.auth-sub{font-size:12px;color:#5a7a9a;margin-bottom:28px;}
.auth-lbl{font-size:11px;font-weight:700;color:#5a7a9a;letter-spacing:1px;margin-bottom:10px;text-align:left;}
.auth-inp{width:100%;padding:13px 16px;background:rgba(6,13,26,0.7);border:1px solid rgba(255,255,255,0.1);border-radius:10px;color:#e8f0fb;font-size:15px;font-family:inherit;text-align:center;outline:none;margin-bottom:14px;letter-spacing:3px;transition:border-color .2s;touch-action:manipulation;}
.auth-inp:focus{border-color:rgba(42,127,255,0.5);}
.auth-btn{width:100%;padding:14px;background:linear-gradient(135deg,#1d5bd4,#2a7fff);color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;font-family:inherit;box-shadow:0 4px 16px rgba(42,127,255,0.3);touch-action:manipulation;transition:opacity .2s;}
.auth-btn:hover{opacity:.9;}
.auth-btn:disabled{opacity:.6;cursor:not-allowed;}
.auth-err{font-size:12px;color:#fca5a5;margin-top:10px;min-height:18px;}
.auth-shake{animation:authShake .4s ease;}
@keyframes authShake{0%,100%{transform:translateX(0)}25%{transform:translateX(-6px)}75%{transform:translateX(6px)}}`;
  document.head.appendChild(s);
}

/* ── 접속 비밀번호 게이트 ── */
async function showAccessGate(onSuccess) {
  if (INOTI_AUTH.isLoggedIn()) { onSuccess(); return; }

  _injectAuthStyle();
  document.body.style.overflow = "hidden";

  const ov = document.createElement("div");
  ov.className = "auth-ov";
  ov.id = "inotiAccessGate";
  ov.innerHTML = `
    <div class="auth-bx">
      <div class="auth-logo">INOTI</div>
      <div class="auth-sub">Eyecare Solution</div>
      <div class="auth-lbl">접속 비밀번호</div>
      <input class="auth-inp" type="password" id="_inoti_apw"
        placeholder="••••••••" autocomplete="off">
      <button class="auth-btn" id="_inoti_abtn">입장하기</button>
      <div class="auth-err" id="_inoti_aerr"></div>
    </div>`;
  document.body.prepend(ov);

  const inp = document.getElementById("_inoti_apw");
  const btn = document.getElementById("_inoti_abtn");
  inp.focus();

  async function tryLogin() {
    btn.disabled = true;
    btn.textContent = "확인 중...";
    try {
      const hash = await INOTI_AUTH._sha256(inp.value);
      if (hash === INOTI_AUTH.ACCESS_HASH) {
        INOTI_AUTH.login();
        ov.style.transition = "opacity .3s";
        ov.style.opacity = "0";
        setTimeout(() => {
          ov.remove();
          document.body.style.overflow = "";
          onSuccess();
        }, 300);
      } else {
        const box = ov.querySelector(".auth-bx");
        box.classList.remove("auth-shake"); void box.offsetWidth; box.classList.add("auth-shake");
        document.getElementById("_inoti_aerr").textContent = "비밀번호가 올바르지 않습니다";
        inp.value = ""; inp.focus();
        btn.disabled = false; btn.textContent = "입장하기";
      }
    } catch(e) {
      btn.disabled = false; btn.textContent = "입장하기";
      document.getElementById("_inoti_aerr").textContent = "오류가 발생했습니다. 다시 시도해주세요.";
    }
  }

  btn.addEventListener("click", tryLogin);
  inp.addEventListener("keydown", e => { if (e.key === "Enter") tryLogin(); });
}

/* ── 관리자 비밀번호 게이트 ── */
async function showAdminGate(onSuccess) {
  if (INOTI_AUTH.isAdmin()) { onSuccess(); return; }

  _injectAuthStyle();
  const ov = document.createElement("div");
  ov.className = "auth-ov"; ov.id = "inotiAdminGate";
  ov.style.background = "rgba(0,0,0,0.85)";
  ov.style.backdropFilter = "blur(8px)";
  ov.innerHTML = `
    <div class="auth-bx">
      <div class="auth-logo" style="font-size:22px;">관리자 인증</div>
      <div class="auth-sub">편집 모드 진입을 위해 관리자 비밀번호를 입력하세요</div>
      <div class="auth-lbl">관리자 비밀번호</div>
      <input class="auth-inp" type="password" id="_inoti_admpw"
        placeholder="••••••••" autocomplete="off">
      <button class="auth-btn" id="_inoti_admbtn">편집 시작</button>
      <div class="auth-err" id="_inoti_admerr"></div>
      <div style="margin-top:14px;">
        <button id="_inoti_admcancel"
          style="background:none;border:none;color:#5a7a9a;font-size:12px;cursor:pointer;font-family:inherit;">
          취소
        </button>
      </div>
    </div>`;
  document.body.prepend(ov);

  const inp = document.getElementById("_inoti_admpw");
  const btn = document.getElementById("_inoti_admbtn");
  inp.focus();

  async function tryAdmin() {
    btn.disabled = true; btn.textContent = "확인 중...";
    try {
      const hash = await INOTI_AUTH._sha256(inp.value);
      if (hash === INOTI_AUTH.ADMIN_HASH) {
        INOTI_AUTH.adminLogin(); ov.remove(); onSuccess();
      } else {
        const box = ov.querySelector(".auth-bx");
        box.classList.remove("auth-shake"); void box.offsetWidth; box.classList.add("auth-shake");
        document.getElementById("_inoti_admerr").textContent = "관리자 비밀번호가 올바르지 않습니다";
        inp.value = ""; inp.focus();
        btn.disabled = false; btn.textContent = "편집 시작";
      }
    } catch(e) {
      btn.disabled = false; btn.textContent = "편집 시작";
    }
  }

  btn.addEventListener("click", tryAdmin);
  inp.addEventListener("keydown", e => { if (e.key === "Enter") tryAdmin(); });
  document.getElementById("_inoti_admcancel").addEventListener("click", () => ov.remove());
}

window.INOTI_AUTH     = INOTI_AUTH;
window.showAccessGate = showAccessGate;
window.showAdminGate  = showAdminGate;
