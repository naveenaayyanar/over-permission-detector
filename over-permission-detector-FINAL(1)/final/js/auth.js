// ===== AUTH MODULE =====
const DEMO_USERS = [
  { id: 1, name: 'Demo User',  email: 'user@demo.com',  password: 'demo123',  role: 'user'  },
  { id: 2, name: 'Demo Admin', email: 'admin@demo.com', password: 'admin123', role: 'admin' },
];

function getUsers() {
  const stored = localStorage.getItem('permguard_users');
  return stored ? JSON.parse(stored) : [...DEMO_USERS];
}
function saveUsers(users) { localStorage.setItem('permguard_users', JSON.stringify(users)); }
function setSession(user) {
  const { password, ...safe } = user;
  localStorage.setItem('permguard_session', JSON.stringify(safe));
}
function getSession() {
  const s = localStorage.getItem('permguard_session');
  return s ? JSON.parse(s) : null;
}
function clearSession() { localStorage.removeItem('permguard_session'); }

function showTab(tab) {
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  const tabLogin = document.getElementById('tabLogin');
  const tabRegister = document.getElementById('tabRegister');
  if (!loginForm) return;
  if (tab === 'login') {
    loginForm.classList.remove('hidden'); registerForm.classList.add('hidden');
    tabLogin.classList.add('active'); tabRegister.classList.remove('active');
  } else {
    registerForm.classList.remove('hidden'); loginForm.classList.add('hidden');
    tabRegister.classList.add('active'); tabLogin.classList.remove('active');
  }
  const msg = document.getElementById('authMsg');
  if (msg) { msg.classList.add('hidden'); msg.textContent = ''; }
}

function showAuthMsg(msg, type = 'error') {
  const el = document.getElementById('authMsg');
  if (!el) return;
  el.textContent = msg; el.className = `auth-msg ${type}`; el.classList.remove('hidden');
}

function handleLogin() {
  const email = document.getElementById('loginEmail')?.value?.trim();
  const password = document.getElementById('loginPassword')?.value;
  if (!email || !password) { showAuthMsg('Please fill in all fields.'); return; }
  const users = getUsers();
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) { showAuthMsg('Invalid email or password.'); return; }
  setSession(user);
  showAuthMsg('Login successful! Redirecting...', 'success');
  setTimeout(() => { window.location.href = 'pages/dashboard.html'; }, 900);
}

function handleRegister() {
  const name = document.getElementById('regName')?.value?.trim();
  const email = document.getElementById('regEmail')?.value?.trim();
  const password = document.getElementById('regPassword')?.value;
  const role = document.getElementById('regRole')?.value;
  if (!name || !email || !password) { showAuthMsg('Please fill in all fields.'); return; }
  if (password.length < 6) { showAuthMsg('Password must be at least 6 characters.'); return; }
  const users = getUsers();
  if (users.find(u => u.email === email)) { showAuthMsg('Email already registered.'); return; }
  const newUser = { id: Date.now(), name, email, password, role };
  users.push(newUser); saveUsers(users);
  setSession(newUser);
  showAuthMsg('Account created! Redirecting...', 'success');
  setTimeout(() => { window.location.href = 'pages/dashboard.html'; }, 900);
}

function loginAsDemo(role) {
  const user = DEMO_USERS.find(u => u.role === role);
  if (user) {
    setSession(user);
    showAuthMsg('Logging in as demo ' + role + '...', 'success');
    setTimeout(() => { window.location.href = 'pages/dashboard.html'; }, 800);
  }
}

// ===== FORGOT PASSWORD =====
function showForgotPassword() {
  const modal = document.getElementById('forgotModal');
  modal.style.display = 'flex';
  document.getElementById('forgotStep1').style.display = 'block';
  document.getElementById('forgotStep2').style.display = 'none';
  document.getElementById('forgotEmail').value = '';
  document.getElementById('forgotMsg').classList.add('hidden');
}
function closeForgotPassword() {
  document.getElementById('forgotModal').style.display = 'none';
}
function showForgotMsg(msg, type = 'error') {
  const el = document.getElementById('forgotMsg');
  el.textContent = msg; el.className = `auth-msg ${type}`; el.classList.remove('hidden');
}
function handleForgotStep1() {
  const email = document.getElementById('forgotEmail').value.trim();
  if (!email) { showForgotMsg('Please enter your email.'); return; }
  const users = getUsers();
  const user = users.find(u => u.email === email);
  if (!user) { showForgotMsg('No account found with that email.'); return; }
  document.getElementById('forgotStep1').style.display = 'none';
  document.getElementById('forgotStep2').style.display = 'block';
  document.getElementById('forgotMsg').classList.add('hidden');
}
function handleForgotStep2() {
  const email = document.getElementById('forgotEmail').value.trim();
  const newPass = document.getElementById('forgotNewPass').value;
  const confirmPass = document.getElementById('forgotConfirmPass').value;
  if (!newPass || newPass.length < 6) { showForgotMsg('Password must be at least 6 characters.'); return; }
  if (newPass !== confirmPass) { showForgotMsg('Passwords do not match.'); return; }
  const users = getUsers();
  const idx = users.findIndex(u => u.email === email);
  if (idx === -1) { showForgotMsg('Account not found.'); return; }
  users[idx].password = newPass;
  saveUsers(users);
  showForgotMsg('Password reset! You can now sign in.', 'success');
  setTimeout(() => closeForgotPassword(), 1800);
}

// Auto-redirect if already logged in
window.addEventListener('DOMContentLoaded', () => {
  const session = getSession();
  const path = window.location.pathname;
  if (session && (path.endsWith('index.html') || path === '/' || path.endsWith('/'))) {
    window.location.href = 'pages/dashboard.html';
  }
  const forgotModal = document.getElementById('forgotModal');
  if (forgotModal) {
    forgotModal.addEventListener('click', function(e) {
      if (e.target === this) closeForgotPassword();
    });
  }
});
