// ============================
// PermGuard AI — Dashboard JS
// ============================

// ===== PERMISSION DATABASE =====
const PERMISSION_DB = {
  'android.permission.CAMERA': { type: 'Dangerous', risk: 'high', desc: 'Access device camera', icon: '📷' },
  'android.permission.RECORD_AUDIO': { type: 'Dangerous', risk: 'high', desc: 'Record audio/microphone', icon: '🎙️' },
  'android.permission.ACCESS_FINE_LOCATION': { type: 'Dangerous', risk: 'medium', desc: 'Precise GPS location', icon: '📍' },
  'android.permission.ACCESS_COARSE_LOCATION': { type: 'Dangerous', risk: 'medium', desc: 'Approximate location', icon: '🗺️' },
  'android.permission.READ_CONTACTS': { type: 'Dangerous', risk: 'high', desc: 'Read contact list', icon: '📒' },
  'android.permission.WRITE_CONTACTS': { type: 'Dangerous', risk: 'high', desc: 'Modify contacts', icon: '✏️' },
  'android.permission.READ_SMS': { type: 'Dangerous', risk: 'high', desc: 'Read SMS messages', icon: '💬' },
  'android.permission.SEND_SMS': { type: 'Dangerous', risk: 'high', desc: 'Send SMS messages', icon: '📤' },
  'android.permission.READ_CALL_LOG': { type: 'Dangerous', risk: 'high', desc: 'Access call history', icon: '📞' },
  'android.permission.PROCESS_OUTGOING_CALLS': { type: 'Dangerous', risk: 'medium', desc: 'Monitor outgoing calls', icon: '📲' },
  'android.permission.READ_EXTERNAL_STORAGE': { type: 'Dangerous', risk: 'medium', desc: 'Read storage/files', icon: '💾' },
  'android.permission.WRITE_EXTERNAL_STORAGE': { type: 'Dangerous', risk: 'medium', desc: 'Write to storage', icon: '📝' },
  'android.permission.GET_ACCOUNTS': { type: 'Dangerous', risk: 'medium', desc: 'Access account list', icon: '👤' },
  'android.permission.USE_BIOMETRIC': { type: 'Special', risk: 'medium', desc: 'Use fingerprint/face ID', icon: '🔏' },
  'android.permission.SYSTEM_ALERT_WINDOW': { type: 'Special', risk: 'high', desc: 'Draw over other apps', icon: '🖥️' },
  'android.permission.BIND_DEVICE_ADMIN': { type: 'Special', risk: 'high', desc: 'Device administrator', icon: '⚙️' },
  'android.permission.INTERNET': { type: 'Normal', risk: 'safe', desc: 'Access the internet', icon: '🌐' },
  'android.permission.VIBRATE': { type: 'Normal', risk: 'safe', desc: 'Control vibration', icon: '📳' },
  'android.permission.RECEIVE_BOOT_COMPLETED': { type: 'Normal', risk: 'safe', desc: 'Run on device boot', icon: '🔄' },
  'android.permission.ACCESS_NETWORK_STATE': { type: 'Normal', risk: 'safe', desc: 'Check network status', icon: '📡' },
  'android.permission.WAKE_LOCK': { type: 'Normal', risk: 'safe', desc: 'Keep CPU awake', icon: '⚡' },
  'android.permission.BLUETOOTH': { type: 'Normal', risk: 'safe', desc: 'Use Bluetooth', icon: '📶' },
  'android.permission.NFC': { type: 'Normal', risk: 'safe', desc: 'Use NFC', icon: '💳' },
  'android.permission.READ_PHONE_STATE': { type: 'Dangerous', risk: 'medium', desc: 'Read device/phone info', icon: '📱' },
  'android.permission.BODY_SENSORS': { type: 'Dangerous', risk: 'medium', desc: 'Access body sensors', icon: '❤️' },
};

const APP_CATEGORIES = ['Social Media', 'Gaming', 'Utility', 'Finance', 'Health & Fitness', 'Entertainment', 'Shopping', 'Education', 'Productivity', 'News'];

// APK templates for demo (simulates different app types)
const APK_PERMISSION_SETS = [
  {
    category: 'Social Media',
    permissions: ['android.permission.CAMERA','android.permission.RECORD_AUDIO','android.permission.READ_CONTACTS','android.permission.ACCESS_FINE_LOCATION','android.permission.READ_EXTERNAL_STORAGE','android.permission.INTERNET','android.permission.VIBRATE','android.permission.RECEIVE_BOOT_COMPLETED','android.permission.ACCESS_NETWORK_STATE']
  },
  {
    category: 'Gaming',
    permissions: ['android.permission.CAMERA','android.permission.ACCESS_FINE_LOCATION','android.permission.READ_CONTACTS','android.permission.READ_SMS','android.permission.SEND_SMS','android.permission.RECORD_AUDIO','android.permission.INTERNET','android.permission.VIBRATE','android.permission.WAKE_LOCK','android.permission.SYSTEM_ALERT_WINDOW']
  },
  {
    category: 'Utility',
    permissions: ['android.permission.INTERNET','android.permission.VIBRATE','android.permission.ACCESS_NETWORK_STATE','android.permission.RECEIVE_BOOT_COMPLETED','android.permission.WAKE_LOCK']
  },
  {
    category: 'Finance',
    permissions: ['android.permission.CAMERA','android.permission.READ_CONTACTS','android.permission.READ_SMS','android.permission.SEND_SMS','android.permission.GET_ACCOUNTS','android.permission.USE_BIOMETRIC','android.permission.INTERNET','android.permission.ACCESS_NETWORK_STATE']
  },
  {
    category: 'Health & Fitness',
    permissions: ['android.permission.BODY_SENSORS','android.permission.ACCESS_FINE_LOCATION','android.permission.CAMERA','android.permission.RECORD_AUDIO','android.permission.READ_CONTACTS','android.permission.READ_SMS','android.permission.INTERNET','android.permission.VIBRATE','android.permission.BIND_DEVICE_ADMIN']
  }
];

// SUSPICIOUS COMBINATIONS
const SUSPICIOUS_COMBOS = [
  { perms: ['android.permission.CAMERA','android.permission.RECORD_AUDIO'], label: 'Covert Recording', severity: 'high', desc: 'Camera + Microphone together can enable covert surveillance without user awareness.' },
  { perms: ['android.permission.READ_SMS','android.permission.SEND_SMS'], label: 'SMS Interception', severity: 'high', desc: 'Reading and sending SMS can be used for OTP theft or premium SMS fraud.' },
  { perms: ['android.permission.READ_CONTACTS','android.permission.INTERNET'], label: 'Contact Exfiltration', severity: 'medium', desc: 'Contact access + internet could allow personal data to be sent to remote servers.' },
  { perms: ['android.permission.ACCESS_FINE_LOCATION','android.permission.RECORD_AUDIO'], label: 'Location + Audio Spy', severity: 'high', desc: 'Location tracking combined with audio recording is a classic spyware pattern.' },
  { perms: ['android.permission.SYSTEM_ALERT_WINDOW','android.permission.RECORD_AUDIO'], label: 'Overlay Attack', severity: 'high', desc: 'Drawing over apps while recording audio is used in screen overlay attacks.' },
  { perms: ['android.permission.READ_CALL_LOG','android.permission.GET_ACCOUNTS'], label: 'Account + Call Tracking', severity: 'medium', desc: 'Access to call logs and account info may enable identity profiling.' },
];

// STATE
let currentAnalysis = null;
let scanHistory = JSON.parse(localStorage.getItem('permguard_history') || '[]');
let allScans = JSON.parse(localStorage.getItem('permguard_all_scans') || '[]');

// ===== INIT =====
document.addEventListener('DOMContentLoaded', () => {
  // Auth guard
  const session = getSession();
  if (!session) { window.location.href = '../index.html'; return; }

  document.getElementById('userName').textContent = session.name;
  document.getElementById('userRole').textContent = session.role;
  document.getElementById('userAvatar').textContent = session.name.charAt(0).toUpperCase();

  if (session.role === 'admin') {
    document.getElementById('adminNav').style.display = 'block';
  }

  loadOverview();
  loadHistory();

  // File input
  const input = document.getElementById('apkInput');
  input.addEventListener('change', (e) => {
    if (e.target.files[0]) startAnalysis(e.target.files[0]);
  });

  // Drag & drop
  const zone = document.getElementById('uploadZone');
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault(); zone.classList.remove('drag-over');
    const f = e.dataTransfer.files[0];
    if (f) startAnalysis(f);
  });
});

function logout() {
  clearSession();
  window.location.href = '../index.html';
}

function showSection(id) {
  document.querySelectorAll('.section-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('sec-' + id).classList.add('active');
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(n => {
    if (n.getAttribute('onclick') && n.getAttribute('onclick').includes(`'${id}'`)) n.classList.add('active');
  });

  if (id === 'admin') loadAdminPanel();
}

// ===== ANALYSIS ENGINE =====
function startAnalysis(file) {
  if (!file.name.endsWith('.apk')) {
    alert('Please upload a valid .apk file.'); return;
  }

  document.getElementById('uploadZone').classList.add('hidden');
  document.getElementById('uploadProgress').classList.remove('hidden');
  document.getElementById('uploadInfo').classList.add('hidden');

  // Pick random APK set + randomize slightly
  const template = APK_PERMISSION_SETS[Math.floor(Math.random() * APK_PERMISSION_SETS.length)];
  const extraPerms = Object.keys(PERMISSION_DB).filter(p => !template.permissions.includes(p));
  const bonus = extraPerms.slice(0, Math.floor(Math.random() * 3));
  const perms = [...new Set([...template.permissions, ...bonus])];

  // Simulate steps
  const steps = ['step1','step2','step3','step4','step5','step6'];
  let stepIdx = 0;

  const interval = setInterval(() => {
    if (stepIdx > 0) document.getElementById(steps[stepIdx-1]).className = 'step done';
    if (stepIdx < steps.length) {
      document.getElementById(steps[stepIdx]).className = 'step active';
      stepIdx++;
    } else {
      clearInterval(interval);
      finishAnalysis(file, template.category, perms);
    }
  }, 600);
}

function finishAnalysis(file, category, permissions) {
  // Compute risk
  const analysis = computeAnalysis(file, category, permissions);
  currentAnalysis = analysis;

  // Save to history
  const session = getSession();
  const record = { ...analysis, user: session?.name || 'Unknown', date: new Date().toLocaleString() };
  scanHistory.unshift(record);
  allScans.unshift(record);
  localStorage.setItem('permguard_history', JSON.stringify(scanHistory.slice(0, 50)));
  localStorage.setItem('permguard_all_scans', JSON.stringify(allScans.slice(0, 200)));

  document.getElementById('uploadProgress').classList.add('hidden');
  document.getElementById('uploadZone').classList.remove('hidden');

  // Populate upload info
  document.getElementById('appName').textContent = file.name;
  document.getElementById('appSize').textContent = formatSize(file.size);
  document.getElementById('appCategory').textContent = category;
  document.getElementById('totalPerms').textContent = permissions.length;
  document.getElementById('dangerPerms').textContent = analysis.dangerous;
  const riskEl = document.getElementById('riskLevelInfo');
  riskEl.textContent = analysis.riskLabel;
  riskEl.style.color = analysis.riskColor;

  document.getElementById('uploadInfo').classList.remove('hidden');

  loadPermissions(analysis);
  loadAIAnalysis(analysis);
  loadRiskScore(analysis);
  loadReports(analysis);
  loadOverview();
  loadHistory();
}

function computeAnalysis(file, category, permissions) {
  const permDetails = permissions.map(p => ({
    name: p.replace('android.permission.', ''),
    full: p,
    ...(PERMISSION_DB[p] || { type: 'Normal', risk: 'safe', desc: 'Unknown permission', icon: '❓' })
  }));

  const dangerous = permDetails.filter(p => p.type === 'Dangerous').length;
  const normal = permDetails.filter(p => p.type === 'Normal').length;
  const special = permDetails.filter(p => p.type === 'Special').length;
  const highRiskCount = permDetails.filter(p => p.risk === 'high').length;
  const medRiskCount = permDetails.filter(p => p.risk === 'medium').length;

  // Detect suspicious combos
  const detectedCombos = SUSPICIOUS_COMBOS.filter(combo =>
    combo.perms.every(p => permissions.includes(p))
  );

  // Score calculation
  let score = 0;
  score += highRiskCount * 12;
  score += medRiskCount * 6;
  score += special * 10;
  score += detectedCombos.filter(c => c.severity === 'high').length * 15;
  score += detectedCombos.filter(c => c.severity === 'medium').length * 8;
  score = Math.min(score, 100);

  let riskLabel, riskColor, riskBg;
  if (score >= 65) { riskLabel = '🔴 High Risk'; riskColor = 'var(--red)'; riskBg = 'rgba(255,61,87,0.1)'; }
  else if (score >= 35) { riskLabel = '🟡 Medium Risk'; riskColor = 'var(--yellow)'; riskBg = 'rgba(255,179,0,0.1)'; }
  else { riskLabel = '🟢 Safe'; riskColor = 'var(--green)'; riskBg = 'rgba(0,230,118,0.1)'; }

  return {
    fileName: file.name,
    fileSize: formatSize(file.size),
    category, permissions, permDetails,
    dangerous, normal, special, highRiskCount, medRiskCount,
    score, riskLabel, riskColor, riskBg,
    detectedCombos, date: new Date().toLocaleString()
  };
}

// ===== LOAD SECTIONS =====
function loadOverview() {
  const history = JSON.parse(localStorage.getItem('permguard_history') || '[]');
  document.getElementById('statTotal').textContent = history.length;
  document.getElementById('statHigh').textContent = history.filter(h => h.score >= 65).length;
  document.getElementById('statMedium').textContent = history.filter(h => h.score >= 35 && h.score < 65).length;
  document.getElementById('statSafe').textContent = history.filter(h => h.score < 35).length;

  if (currentAnalysis) {
    const a = currentAnalysis;
    const total = a.permissions.length;
    const barsEl = document.getElementById('overviewBarChart');
    barsEl.innerHTML = `
      <div class="bar-row">
        <div class="bar-meta"><span>Dangerous Permissions</span><span style="color:var(--red)">${a.dangerous} found</span></div>
        <div class="bar-track"><div class="bar-fill" style="width:${(a.dangerous/total*100).toFixed(0)}%;background:var(--red)"></div></div>
      </div>
      <div class="bar-row">
        <div class="bar-meta"><span>Normal Permissions</span><span style="color:var(--green)">${a.normal} found</span></div>
        <div class="bar-track"><div class="bar-fill" style="width:${(a.normal/total*100).toFixed(0)}%;background:var(--green)"></div></div>
      </div>
      <div class="bar-row">
        <div class="bar-meta"><span>Special Permissions</span><span style="color:var(--yellow)">${a.special} found</span></div>
        <div class="bar-track"><div class="bar-fill" style="width:${(a.special/total*100).toFixed(0)}%;background:var(--yellow)"></div></div>
      </div>
    `;
  }

  if (history.length > 0) {
    const recent = history.slice(0, 4);
    document.getElementById('recentScans').innerHTML = recent.map(r => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);">
        <div>
          <div style="font-size:0.88rem;font-weight:600;">${r.fileName}</div>
          <div style="font-size:0.78rem;color:var(--text-muted);">${r.category} • ${r.date}</div>
        </div>
        <div style="color:${r.riskColor};font-size:0.82rem;font-weight:700;">${r.riskLabel}</div>
      </div>
    `).join('');
  }
}

function loadPermissions(a) {
  document.getElementById('noPermData').style.display = 'none';
  document.getElementById('permData').classList.remove('hidden');

  const tbody = document.getElementById('permTableBody');
  tbody.innerHTML = a.permDetails.map(p => `
    <tr>
      <td>${p.icon} ${p.name}</td>
      <td style="color:${p.type==='Dangerous'?'var(--red)':p.type==='Special'?'var(--yellow)':'var(--green)'}">${p.type}</td>
      <td><span class="risk-chip ${p.risk==='high'?'high':p.risk==='medium'?'medium':'safe'}">${p.risk.toUpperCase()}</span></td>
    </tr>
  `).join('');

  // Draw pie chart on canvas
  const canvas = document.getElementById('permChart');
  const ctx = canvas.getContext('2d');
  const data = [
    { label: 'Dangerous', count: a.dangerous, color: '#ff3d57' },
    { label: 'Normal', count: a.normal, color: '#00e676' },
    { label: 'Special', count: a.special, color: '#ffb300' },
  ].filter(d => d.count > 0);

  const total = data.reduce((s, d) => s + d.count, 0);
  let startAngle = -Math.PI / 2;
  const cx = 130, cy = 130, r = 110;

  ctx.clearRect(0, 0, 260, 260);
  data.forEach(d => {
    const slice = (d.count / total) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, startAngle, startAngle + slice);
    ctx.closePath();
    ctx.fillStyle = d.color;
    ctx.fill();
    startAngle += slice;
  });
  // Center hole
  ctx.beginPath();
  ctx.arc(cx, cy, 55, 0, 2 * Math.PI);
  ctx.fillStyle = '#0f1825';
  ctx.fill();
  // Center text
  ctx.fillStyle = '#e8eef8';
  ctx.font = 'bold 22px Space Mono';
  ctx.textAlign = 'center';
  ctx.fillText(total, cx, cy + 8);

  document.getElementById('permLegend').innerHTML = data.map(d => `
    <div class="legend-item"><div class="legend-dot" style="background:${d.color}"></div>${d.label}: <strong>${d.count}</strong></div>
  `).join('');
}

function loadAIAnalysis(a) {
  document.getElementById('noAIData').style.display = 'none';
  document.getElementById('aiData').classList.remove('hidden');

  // Unnecessary permissions by category
  const categoryNeedMap = {
    'Gaming': ['android.permission.INTERNET','android.permission.VIBRATE','android.permission.WAKE_LOCK'],
    'Utility': ['android.permission.INTERNET','android.permission.VIBRATE','android.permission.ACCESS_NETWORK_STATE'],
    'Social Media': ['android.permission.CAMERA','android.permission.RECORD_AUDIO','android.permission.INTERNET','android.permission.ACCESS_FINE_LOCATION'],
    'Finance': ['android.permission.INTERNET','android.permission.USE_BIOMETRIC','android.permission.CAMERA'],
    'Health & Fitness': ['android.permission.BODY_SENSORS','android.permission.ACCESS_FINE_LOCATION','android.permission.INTERNET'],
  };

  const expected = categoryNeedMap[a.category] || [];
  const unnecessary = a.permissions.filter(p => {
    const info = PERMISSION_DB[p];
    return info && (info.risk === 'high' || info.risk === 'medium') && !expected.includes(p);
  });

  document.getElementById('aiFindings').innerHTML = `
    <div class="alert ${unnecessary.length > 3 ? 'error' : unnecessary.length > 0 ? 'warn' : 'success'}">
      ${unnecessary.length > 3 ? '🔴' : unnecessary.length > 0 ? '🟡' : '🟢'} 
      AI detected <strong>${unnecessary.length}</strong> potentially unnecessary permission(s) for a <strong>${a.category}</strong> app.
    </div>
    ${unnecessary.map(p => {
      const info = PERMISSION_DB[p] || {};
      return `<div style="display:flex;align-items:center;gap:10px;padding:10px;background:var(--bg2);border-radius:8px;margin-top:8px;font-size:0.85rem;">
        <span style="font-size:1.2rem">${info.icon||'❓'}</span>
        <div>
          <div style="font-weight:600;">${p.replace('android.permission.','')}</div>
          <div style="color:var(--text-muted);font-size:0.78rem;">${info.desc || ''} — not typical for ${a.category}</div>
        </div>
        <span class="risk-chip high" style="margin-left:auto">Unnecessary</span>
      </div>`;
    }).join('')}
  `;

  document.getElementById('suspiciousCombos').innerHTML = a.detectedCombos.length === 0
    ? '<div class="alert success">✅ No suspicious permission combinations detected.</div>'
    : a.detectedCombos.map(c => `
        <div style="background:var(--bg2);border:1px solid rgba(255,61,87,0.2);border-radius:8px;padding:14px;margin-bottom:10px;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
            <span class="risk-chip ${c.severity}">${c.severity.toUpperCase()}</span>
            <strong>${c.label}</strong>
          </div>
          <div style="color:var(--text-muted);font-size:0.84rem;">${c.desc}</div>
          <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">
            ${c.perms.map(p=>`<span style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:2px 8px;font-size:0.75rem;font-family:var(--font-mono)">${p.replace('android.permission.','')}</span>`).join('')}
          </div>
        </div>`
      ).join('');

  document.getElementById('aiDetailReport').innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;">
      <div style="background:var(--bg2);border-radius:8px;padding:16px;text-align:center;">
        <div style="font-family:var(--font-mono);font-size:1.8rem;font-weight:700;color:var(--red)">${a.highRiskCount}</div>
        <div style="color:var(--text-muted);font-size:0.82rem;margin-top:4px;">High Risk Permissions</div>
      </div>
      <div style="background:var(--bg2);border-radius:8px;padding:16px;text-align:center;">
        <div style="font-family:var(--font-mono);font-size:1.8rem;font-weight:700;color:var(--yellow)">${a.medRiskCount}</div>
        <div style="color:var(--text-muted);font-size:0.82rem;margin-top:4px;">Medium Risk Permissions</div>
      </div>
      <div style="background:var(--bg2);border-radius:8px;padding:16px;text-align:center;">
        <div style="font-family:var(--font-mono);font-size:1.8rem;font-weight:700;color:var(--accent)">${a.detectedCombos.length}</div>
        <div style="color:var(--text-muted);font-size:0.82rem;margin-top:4px;">Suspicious Combinations</div>
      </div>
    </div>
    <div style="margin-top:16px;padding:14px;background:var(--bg2);border-radius:8px;color:var(--text-muted);font-size:0.88rem;line-height:1.7;">
      <strong style="color:var(--text)">AI Summary:</strong> This <strong>${a.category}</strong> app requests ${a.permissions.length} total permissions, 
      of which ${a.dangerous} are classified as Dangerous. 
      ${a.detectedCombos.length > 0 ? `The AI engine identified ${a.detectedCombos.length} suspicious permission combination(s) that could indicate malicious behavior.` : 'No suspicious permission combinations were detected.'}
      Overall risk score is <strong style="color:${a.riskColor}">${a.score}/100</strong>.
    </div>
  `;
}

function loadRiskScore(a) {
  document.getElementById('noRiskData').style.display = 'none';
  document.getElementById('riskData').classList.remove('hidden');

  const gv = document.getElementById('gaugeValue');
  gv.textContent = a.score;
  gv.style.color = a.riskColor;

  const gf = document.getElementById('gaugeFill');
  gf.style.background = `linear-gradient(90deg, ${a.score>=65?'var(--yellow),var(--red)':a.score>=35?'var(--green),var(--yellow)':'var(--green),var(--green)'})`;
  setTimeout(() => { gf.style.width = a.score + '%'; }, 100);

  const badge = document.getElementById('riskBadgeLarge');
  badge.textContent = a.riskLabel;
  badge.style.background = a.riskBg;
  badge.style.color = a.riskColor;
  badge.style.border = `1px solid ${a.riskColor}`;

  document.getElementById('riskFactors').innerHTML = [
    { label: 'High Risk Permissions', val: a.highRiskCount * 12, max: 60, color: 'var(--red)' },
    { label: 'Medium Risk Permissions', val: a.medRiskCount * 6, max: 40, color: 'var(--yellow)' },
    { label: 'Special Permissions', val: a.special * 10, max: 30, color: 'var(--accent)' },
    { label: 'Suspicious Combos', val: a.detectedCombos.length * 10, max: 40, color: 'var(--accent2)' },
  ].map(f => `
    <div class="bar-row">
      <div class="bar-meta"><span>${f.label}</span><span style="color:${f.color}">${Math.min(f.val,f.max)} pts</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.min(100, (f.val/f.max)*100)}%;background:${f.color}"></div></div>
    </div>
  `).join('');

  const recs = [];
  if (a.highRiskCount > 0) recs.push({ icon: '🔴', text: `Remove or justify ${a.highRiskCount} high-risk permission(s). These should only be requested if absolutely essential to core functionality.` });
  if (a.detectedCombos.length > 0) recs.push({ icon: '⚠️', text: `${a.detectedCombos.length} suspicious permission combination(s) detected. Review if these combinations are necessary for the app's stated purpose.` });
  if (a.special > 0) recs.push({ icon: '🟡', text: `${a.special} special system permission(s) found. These require explicit user approval and should be avoided unless critical.` });
  if (a.score < 35) recs.push({ icon: '✅', text: 'App appears safe with minimal over-permission concerns. Continue monitoring future updates.' });

  document.getElementById('recommendations').innerHTML = recs.length === 0
    ? '<div class="alert success">✅ No major concerns detected.</div>'
    : recs.map(r => `<div class="alert ${r.icon==='✅'?'success':r.icon==='🔴'?'error':'warn'}" style="margin-bottom:10px;">${r.icon} ${r.text}</div>`).join('');
}

function loadReports(a) {
  document.getElementById('noReportData').style.display = 'none';
  document.getElementById('reportData').classList.remove('hidden');

  document.getElementById('reportPreview').innerHTML = `
    <div style="border:1px solid var(--border);border-radius:8px;padding:24px;background:var(--bg2);">
      <h2 style="font-family:var(--font-display);font-size:1.4rem;margin-bottom:4px;">PermGuard AI — Security Report</h2>
      <p style="color:var(--text-muted);font-size:0.85rem;margin-bottom:20px;">Generated: ${a.date}</p>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px;">
        <div><span style="color:var(--text-muted);font-size:0.78rem;">App File</span><div style="font-weight:600;">${a.fileName}</div></div>
        <div><span style="color:var(--text-muted);font-size:0.78rem;">Category</span><div style="font-weight:600;">${a.category}</div></div>
        <div><span style="color:var(--text-muted);font-size:0.78rem;">Total Permissions</span><div style="font-weight:600;">${a.permissions.length}</div></div>
        <div><span style="color:var(--text-muted);font-size:0.78rem;">Risk Score</span><div style="font-weight:700;color:${a.riskColor}">${a.score}/100 — ${a.riskLabel}</div></div>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:0.83rem;">
        <tr style="color:var(--text-muted);border-bottom:1px solid var(--border);">
          <th style="text-align:left;padding:8px;">Permission</th>
          <th style="text-align:left;padding:8px;">Type</th>
          <th style="text-align:left;padding:8px;">Risk Level</th>
        </tr>
        ${a.permDetails.map(p=>`
          <tr style="border-bottom:1px solid rgba(30,45,69,0.3);">
            <td style="padding:8px;">${p.icon} ${p.name}</td>
            <td style="padding:8px;color:${p.type==='Dangerous'?'var(--red)':p.type==='Special'?'var(--yellow)':'var(--green)'}">${p.type}</td>
            <td style="padding:8px;"><span class="risk-chip ${p.risk==='high'?'high':p.risk==='medium'?'medium':'safe'}">${p.risk}</span></td>
          </tr>`).join('')}
      </table>
    </div>
  `;
}

function loadHistory() {
  const history = JSON.parse(localStorage.getItem('permguard_history') || '[]');
  const tbody = document.getElementById('historyTableBody');
  if (history.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:40px;">No scan history yet.</td></tr>';
    return;
  }
  tbody.innerHTML = history.map(r => `
    <tr>
      <td>${r.fileName}</td>
      <td>${r.category}</td>
      <td>${r.permissions.length}</td>
      <td style="font-family:var(--font-mono);color:${r.riskColor}">${r.score}</td>
      <td><span class="risk-chip ${r.score>=65?'high':r.score>=35?'medium':'safe'}">${r.riskLabel}</span></td>
      <td style="color:var(--text-muted);font-size:0.82rem;">${r.date}</td>
    </tr>
  `).join('');
}

function loadAdminPanel() {
  const users = getUsers();
  const allScans = JSON.parse(localStorage.getItem('permguard_all_scans') || '[]');

  document.getElementById('adminTotalUsers').textContent = users.length;
  document.getElementById('adminAdmins').textContent = users.filter(u => u.role === 'admin').length;
  document.getElementById('adminTotalScans').textContent = allScans.length;
  document.getElementById('adminHighRisk').textContent = allScans.filter(s => s.score >= 65).length;

  document.getElementById('adminUsersTable').innerHTML = users.map((u, i) => `
    <tr>
      <td>${i+1}</td>
      <td>${u.name}</td>
      <td>${u.email}</td>
      <td><span class="risk-chip ${u.role==='admin'?'medium':'safe'}">${u.role}</span></td>
      <td style="color:var(--text-muted);font-size:0.82rem;">Account registered</td>
    </tr>
  `).join('');

  document.getElementById('adminScansTable').innerHTML = allScans.length === 0
    ? '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:30px;">No scans yet.</td></tr>'
    : allScans.slice(0, 30).map(s => `
      <tr>
        <td>${s.fileName}</td>
        <td style="font-family:var(--font-mono);color:${s.riskColor}">${s.score}/100</td>
        <td>${s.riskLabel}</td>
        <td>${s.user || '—'}</td>
        <td style="color:var(--text-muted);font-size:0.82rem;">${s.date}</td>
      </tr>`).join('');
}

// ===== EXPORT FUNCTIONS =====
function downloadHTML() {
  if (!currentAnalysis) return;
  const a = currentAnalysis;
  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>PermGuard AI Report — ${a.fileName}</title>
<style>body{font-family:Arial,sans-serif;background:#f5f7fa;color:#222;margin:0;padding:24px;}
.container{max-width:800px;margin:0 auto;background:#fff;border-radius:8px;padding:32px;box-shadow:0 2px 12px rgba(0,0,0,0.1);}
h1{color:#7b5cff;}table{width:100%;border-collapse:collapse;margin-top:16px;}
th{background:#f0f4ff;padding:10px;text-align:left;}td{padding:10px;border-bottom:1px solid #eee;}
.high{color:#e53935;font-weight:700;}.medium{color:#fb8c00;font-weight:700;}.safe{color:#43a047;font-weight:700;}
.badge{display:inline-block;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:700;}
.badge.high{background:#fde8e8;color:#e53935;}.badge.medium{background:#fff3e0;color:#fb8c00;}.badge.safe{background:#e8f5e9;color:#43a047;}
</style></head><body><div class="container">
<h1>🛡️ PermGuard AI — Security Report</h1>
<p><strong>App:</strong> ${a.fileName} | <strong>Category:</strong> ${a.category} | <strong>Date:</strong> ${a.date}</p>
<p><strong>Risk Score:</strong> <span class="${a.score>=65?'high':a.score>=35?'medium':'safe'}">${a.score}/100 — ${a.riskLabel}</span></p>
<p><strong>Total Permissions:</strong> ${a.permissions.length} (${a.dangerous} Dangerous, ${a.normal} Normal, ${a.special} Special)</p>
<h2>Permissions Detail</h2>
<table><tr><th>Permission</th><th>Type</th><th>Risk Level</th><th>Description</th></tr>
${a.permDetails.map(p=>`<tr><td>${p.icon} ${p.name}</td><td>${p.type}</td><td><span class="badge ${p.risk==='high'?'high':p.risk==='medium'?'medium':'safe'}">${p.risk}</span></td><td>${p.desc}</td></tr>`).join('')}
</table>
<h2>Suspicious Combinations (${a.detectedCombos.length})</h2>
${a.detectedCombos.length===0?'<p>None detected.</p>':a.detectedCombos.map(c=>`<p>⚠️ <strong>${c.label}</strong> — ${c.desc}</p>`).join('')}
<hr>
</div></body></html>`;
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url; link.download = `permguard-report-${Date.now()}.html`; link.click();
}

function downloadJSON() {
  if (!currentAnalysis) return;
  const blob = new Blob([JSON.stringify(currentAnalysis, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url; link.download = `permguard-data-${Date.now()}.json`; link.click();
}

function downloadPDF() {
  if (!currentAnalysis) return;
  const a = currentAnalysis;
  try {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.setFontSize(18); doc.setTextColor(123, 92, 255);
    doc.text('PermGuard AI - Security Report', 14, 20);
    doc.setFontSize(11); doc.setTextColor(50, 50, 50);
    doc.text(`App: ${a.fileName}`, 14, 32);
    doc.text(`Category: ${a.category}`, 14, 40);
    doc.text(`Date: ${a.date}`, 14, 48);
    doc.text(`Risk Score: ${a.score}/100 — ${a.riskLabel.replace(/[^\w\s\/\-]/g,'')}`, 14, 56);
    doc.text(`Total Permissions: ${a.permissions.length} (Dangerous: ${a.dangerous}, Normal: ${a.normal}, Special: ${a.special})`, 14, 64);
    let y = 76;
    doc.setFontSize(13); doc.setTextColor(0,0,0);
    doc.text('Permissions:', 14, y); y += 8;
    doc.setFontSize(10);
    a.permDetails.forEach(p => {
      if (y > 270) { doc.addPage(); y = 20; }
      doc.setTextColor(p.risk==='high'?220:p.risk==='medium'?180:0, p.risk==='safe'?180:0, 0);
      doc.text(`${p.name} [${p.type}] — ${p.risk}`, 14, y); y += 7;
    });
    if (a.detectedCombos.length > 0) {
      if (y > 250) { doc.addPage(); y = 20; }
      doc.setFontSize(13); doc.setTextColor(0,0,0);
      doc.text('Suspicious Combinations:', 14, y); y += 8;
      doc.setFontSize(10);
      a.detectedCombos.forEach(c => {
        if (y > 270) { doc.addPage(); y = 20; }
        doc.setTextColor(200,0,0);
        doc.text(`${c.label}: ${c.desc}`, 14, y); y += 7;
      });
    }
    doc.setFontSize(9); doc.setTextColor(150,150,150);
    doc.save(`permguard-report-${Date.now()}.pdf`);
  } catch(e) {
    alert('PDF library not loaded. Please download HTML report instead.');
  }
}

function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B','KB','MB','GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
