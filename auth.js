/* ══════════════════════════════════════════════════
   auth.js — INOTI 공통 인증 모듈
   
   · 접속 비밀번호:  inoti8300
   · 관리자 비밀번호: @@inoti8300!!
   
   사용법: 각 HTML 파일 <head>에 아래 추가
   <script src="auth.js"></script>
══════════════════════════════════════════════════ */

const INOTI_AUTH = {
  ACCESS_PW:  "inoti8300",
  ADMIN_PW:   "@@inoti8300!!",
  SESSION_KEY: "inoti_access",
  ADMIN_KEY:   "inoti_admin",
  SESSION_MIN: 1440,  // 접속 세션 유지 시간 (분) — 8시간

  /* 접속 인증 확인 */
  isLoggedIn() {
    const t = localStorage.getItem(this.SESSION_KEY);
    if(!t) return false;
    const elapsed = (Date.now() - parseInt(t)) / 60000;
    return elapsed < this.SESSION_MIN;
  },

  /* 관리자 인증 확인 */
  isAdmin() {
    const t = localStorage.getItem(this.ADMIN_KEY);
    if(!t) return false;
    const elapsed = (Date.now() - parseInt(t)) / 60000;
    return elapsed < 60; // 관리자 모드 1시간 유지
  },

  /* 접속 로그인 */
  login()      { localStorage.setItem(this.SESSION_KEY, Date.now()); },

  /* 관리자 로그인 */
  adminLogin() { localStorage.setItem(this.ADMIN_KEY, Date.now()); },

  /* 관리자 로그아웃 */
  adminLogout(){ localStorage.removeItem(this.ADMIN_KEY); },

  /* 전체 로그아웃 */
  logout() {
    localStorage.removeItem(this.SESSION_KEY);
    localStorage.removeItem(this.ADMIN_KEY);
  }
};

/* ── 공통 잠금 화면 스타일 ── */
const AUTH_STYLE = `
<style id="auth-style">
.auth-overlay {
  position:fixed;inset:0;
  background:linear-gradient(135deg,#060d1a 0%,#0d1b2e 100%);
  display:flex;align-items:center;justify-content:center;
  z-index:9999;
  font-family:'Noto Sans KR',sans-serif;
}
.auth-box {
  background:rgba(13,27,46,0.95);
  border:1px solid rgba(255,255,255,0.1);
  border-radius:20px;
  padding:40px 36px;
  width:340px;
  text-align:center;
  box-shadow:0 24px 80px rgba(0,0,0,0.6);
  animation:authFadeIn .4s ease;
}
@keyframes authFadeIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
.auth-logo {
  font-family:'DM Serif Display',serif;
  font-size:28px;
  color:#e8f0fb;
  margin-bottom:6px;
  letter-spacing:1px;
}
.auth-sub {
  font-size:12px;
  color:#5a7a9a;
  margin-bottom:28px;
}
.auth-label {
  font-size:11px;
  font-weight:700;
  color:#5a7a9a;
  letter-spacing:1px;
  margin-bottom:10px;
  text-align:left;
}
.auth-input {
  width:100%;
  padding:13px 16px;
  background:rgba(6,13,26,0.7);
  border:1px solid rgba(255,255,255,0.1);
  border-radius:10px;
  color:#e8f0fb;
  font-size:15px;
  font-family:'Noto Sans KR',sans-serif;
  text-align:center;
  outline:none;
  transition:border-color .2s;
  margin-bottom:14px;
  letter-spacing:2px;
}
.auth-input:focus { border-color:rgba(42,127,255,0.5); }
.auth-btn {
  width:100%;
  padding:14px;
  background:linear-gradient(135deg,#1d5bd4,#2a7fff);
  color:white;
  border:none;
  border-radius:10px;
  font-size:15px;
  font-weight:700;
  cursor:pointer;
  font-family:'Noto Sans KR',sans-serif;
  transition:all .2s;
  box-shadow:0 4px 16px rgba(42,127,255,0.3);
}
.auth-btn:hover { transform:translateY(-1px);box-shadow:0 6px 20px rgba(42,127,255,0.4); }
.auth-error {
  font-size:12px;
  color:#fca5a5;
  margin-top:10px;
  min-height:18px;
}
.auth-shake { animation:shake .4s ease; }
@keyframes shake{0%,100%{transform:translateX(0)}25%{transform:translateX(-6px)}75%{transform:translateX(6px)}}
</style>`;

/* ── 접속 비밀번호 게이트 ── */
function showAccessGate(onSuccess) {
  if(INOTI_AUTH.isLoggedIn()) { onSuccess(); return; }

  document.head.insertAdjacentHTML("beforeend", AUTH_STYLE);
  document.body.style.overflow = "hidden";

  const overlay = document.createElement("div");
  overlay.className = "auth-overlay";
  overlay.id = "accessGate";
  overlay.innerHTML = `
    <div class="auth-box">
      <div class="auth-logo">INOTI</div>
      <div class="auth-sub">Eyecare Solution</div>
      <div class="auth-label">접속 비밀번호</div>
      <input class="auth-input" type="password" id="accessPwInput"
        placeholder="••••••••" autocomplete="off"
        onkeydown="if(event.key==='Enter') checkAccessPw()">
      <button class="auth-btn" onclick="checkAccessPw()">입장하기</button>
      <div class="auth-error" id="accessError"></div>
    </div>`;
  document.body.prepend(overlay);
  document.getElementById("accessPwInput").focus();

  window.checkAccessPw = function() {
    const pw = document.getElementById("accessPwInput").value;
    if(pw === INOTI_AUTH.ACCESS_PW) {
      INOTI_AUTH.login();
      document.getElementById("accessGate").style.opacity = "0";
      document.getElementById("accessGate").style.transition = "opacity .3s";
      setTimeout(() => {
        document.getElementById("accessGate").remove();
        document.body.style.overflow = "";
        onSuccess();
      }, 300);
    } else {
      const box = document.querySelector("#accessGate .auth-box");
      box.classList.remove("auth-shake");
      void box.offsetWidth;
      box.classList.add("auth-shake");
      document.getElementById("accessError").textContent = "비밀번호가 올바르지 않습니다";
      document.getElementById("accessPwInput").value = "";
      document.getElementById("accessPwInput").focus();
    }
  };
}

/* ── 관리자 편집 비밀번호 확인 ── */
function showAdminGate(onSuccess) {
  if(INOTI_AUTH.isAdmin()) { onSuccess(); return; }

  document.head.insertAdjacentHTML("beforeend", AUTH_STYLE);

  const overlay = document.createElement("div");
  overlay.className = "auth-overlay";
  overlay.id = "adminGate";
  overlay.style.background = "rgba(0,0,0,0.85)";
  overlay.style.backdropFilter = "blur(8px)";
  overlay.innerHTML = `
    <div class="auth-box">
      <div class="auth-logo" style="font-size:22px;">🔐 관리자 인증</div>
      <div class="auth-sub">편집 모드 진입을 위해 관리자 비밀번호를 입력하세요</div>
      <div class="auth-label">관리자 비밀번호</div>
      <input class="auth-input" type="password" id="adminPwInput"
        placeholder="••••••••" autocomplete="off"
        onkeydown="if(event.key==='Enter') checkAdminPw()">
      <button class="auth-btn" onclick="checkAdminPw()">편집 시작</button>
      <div class="auth-error" id="adminError"></div>
      <div style="margin-top:14px;">
        <button onclick="document.getElementById('adminGate').remove()"
          style="background:none;border:none;color:#5a7a9a;font-size:12px;cursor:pointer;font-family:'Noto Sans KR',sans-serif;">
          취소
        </button>
      </div>
    </div>`;
  document.body.prepend(overlay);
  document.getElementById("adminPwInput").focus();

  window.checkAdminPw = function() {
    const pw = document.getElementById("adminPwInput").value;
    if(pw === INOTI_AUTH.ADMIN_PW) {
      INOTI_AUTH.adminLogin();
      document.getElementById("adminGate").remove();
      onSuccess();
    } else {
      const box = document.querySelector("#adminGate .auth-box");
      box.classList.remove("auth-shake");
      void box.offsetWidth;
      box.classList.add("auth-shake");
      document.getElementById("adminError").textContent = "관리자 비밀번호가 올바르지 않습니다";
      document.getElementById("adminPwInput").value = "";
      document.getElementById("adminPwInput").focus();
    }
  };
}

/* ══════════════════════════════════════════════════
   [FIX] window 명시 등록
   — const/let 선언은 브라우저 환경에 따라 window에
     자동 등록되지 않을 수 있어 명시적으로 등록
══════════════════════════════════════════════════ */
window.INOTI_AUTH      = INOTI_AUTH;
window.showAccessGate  = showAccessGate;
window.showAdminGate   = showAdminGate;
