/* ══════════════════════════════════════════════════
   firebase-config.js  —  inoti-book
   Firebase SDK v12 (ESM 모듈 방식)
══════════════════════════════════════════════════ */

import { initializeApp }              from "https://www.gstatic.com/firebasejs/12.13.0/firebase-app.js";
import { getFirestore,
         collection, doc,
         getDoc, getDocs,
         setDoc, addDoc, updateDoc, deleteDoc,
         query, where, orderBy, limit,
         onSnapshot, serverTimestamp }  from "https://www.gstatic.com/firebasejs/12.13.0/firebase-firestore.js";

/* ── 프로젝트 설정 ── */
const firebaseConfig = {
  apiKey:            "AIzaSyASSGlGKYkE1icXzyyvxZeQqmy_iNhLd8o",
  authDomain:        "inoti-book.firebaseapp.com",
  projectId:         "inoti-book",
  storageBucket:     "inoti-book.firebasestorage.app",
  messagingSenderId: "29678936176",
  appId:             "1:29678936176:web:3e9605220fd07a929d54b5"
};

/* ── 초기화 ── */
const app = initializeApp(firebaseConfig);
const db  = getFirestore(app);

console.log("✅ Firebase inoti-book 연결됨");

/* ── 외부 사용을 위해 export ── */
export {
  db,
  collection, doc,
  getDoc, getDocs,
  setDoc, addDoc, updateDoc, deleteDoc,
  query, where, orderBy, limit,
  onSnapshot, serverTimestamp
};
