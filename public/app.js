/* ============================================
   Chess Arena — Client Application
   With security: email verify, forgot password,
   Google Sign-In, password strength
   ============================================ */

const socket = io();

// ---- Chess piece Unicode mappings ----
const PIECE_UNICODE = {
    wp: '♙', wn: '♘', wb: '♗', wr: '♖', wq: '♕', wk: '♔',
    bp: '♟', bn: '♞', bb: '♝', br: '♜', bq: '♛', bk: '♚'
};

// ---- State ----
let currentUser = null;
let myColor = null;
let selectedSquare = null;
let legalMoves = [];
let lastMove = null;
let gameActive = false;
let moveHistory = [];
let pendingPromotion = null;
let selectedTimeControl = 'blitz';
let chess = null;
let pendingVerifyEmail = null;

// ---- Sound System (Web Audio API) ----
const AudioCtx = window.AudioContext || window.webkitAudioContext;
let audioCtx = null;
function ensureAudio() { if (!audioCtx) audioCtx = new AudioCtx(); }

function playTone(freq, duration, type = 'sine', volume = 0.15) {
    ensureAudio();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, audioCtx.currentTime);
    gain.gain.setValueAtTime(volume, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + duration);
    osc.connect(gain); gain.connect(audioCtx.destination);
    osc.start(); osc.stop(audioCtx.currentTime + duration);
}
function playMoveSound() { playTone(600, 0.08, 'sine', 0.12); setTimeout(() => playTone(800, 0.06, 'sine', 0.08), 40); }
function playCaptureSound() { playTone(300, 0.12, 'square', 0.1); setTimeout(() => playTone(200, 0.1, 'square', 0.08), 50); }
function playCheckSound() { playTone(880, 0.1, 'sawtooth', 0.12); setTimeout(() => playTone(1100, 0.15, 'sawtooth', 0.1), 80); setTimeout(() => playTone(880, 0.1, 'sawtooth', 0.08), 180); }
function playCheckmateSound() { playTone(440, 0.15, 'sawtooth', 0.15); setTimeout(() => playTone(554, 0.15, 'sawtooth', 0.12), 150); setTimeout(() => playTone(659, 0.15, 'sawtooth', 0.12), 300); setTimeout(() => playTone(880, 0.3, 'sawtooth', 0.15), 450); }
function playGameStartSound() { playTone(523, 0.1, 'sine', 0.1); setTimeout(() => playTone(659, 0.1, 'sine', 0.1), 100); setTimeout(() => playTone(784, 0.15, 'sine', 0.12), 200); }
function playCastleSound() { playTone(500, 0.06, 'sine', 0.1); setTimeout(() => playTone(700, 0.06, 'sine', 0.1), 60); setTimeout(() => playTone(500, 0.06, 'sine', 0.08), 120); }

// ---- DOM Shortcuts ----
const $ = (id) => document.getElementById(id);

// Auth elements
const authScreen = $('auth-screen');
const mainApp = $('main-app');
const loginForm = $('login-form');
const signupForm = $('signup-form');
const verifyForm = $('verify-form');
const forgotForm = $('forgot-form');
const loginEmail = $('login-email');
const loginPassword = $('login-password');
const btnLogin = $('btn-login');
const loginError = $('login-error');
const signupUsername = $('signup-username');
const signupEmail = $('signup-email');
const signupPassword = $('signup-password');
const btnSignup = $('btn-signup');
const signupError = $('signup-error');
const showSignup = $('show-signup');
const showLogin = $('show-login');
const showForgot = $('show-forgot');
const btnGuest = $('btn-guest');
const btnLogout = $('btn-logout');
const navUsername = $('nav-username');
const verifiedBadge = $('verified-badge');

// Verify elements
const verifyCode = $('verify-code');
const btnVerify = $('btn-verify');
const verifyError = $('verify-error');
const verifyEmailDisplay = $('verify-email-display');
const btnResendCode = $('btn-resend-code');
const btnBackToLogin = $('btn-back-to-login');
const devCodeDisplay = $('dev-code-display');
const devCodeValue = $('dev-code-value');

// Forgot password
const forgotEmail = $('forgot-email');
const btnSendReset = $('btn-send-reset');
const forgotError = $('forgot-error');
const forgotStep1 = $('forgot-step-1');
const forgotStep2 = $('forgot-step-2');
const resetCode = $('reset-code');
const newPassword = $('new-password');
const confirmPassword = $('confirm-password');
const btnResetPassword = $('btn-reset-password');
const resetError = $('reset-error');
const btnBackFromForgot = $('btn-back-from-forgot');
const forgotDevCode = $('forgot-dev-code');
const forgotDevCodeValue = $('forgot-dev-code-value');

// Google
const btnGoogleSignin = $('btn-google-signin');
const btnGoogleSignup = $('btn-google-signup');

// Password strength
const passwordStrength = $('password-strength');

// Game screens
const lobbyScreen = $('lobby-screen');
const waitingScreen = $('waiting-screen');
const gameScreen = $('game-screen');
const btnCreate = $('btn-create');
const btnJoin = $('btn-join');
const roomCodeInput = $('room-code-input');
const lobbyError = $('lobby-error');
const displayRoomCode = $('display-room-code');
const btnCopyCode = $('btn-copy-code');
const btnCancelWait = $('btn-cancel-wait');
const waitingTimeLabel = $('waiting-time-label');
const chessBoard = $('chess-board');
const statusText = $('status-text');
const gameRoomCode = $('game-room-code');
const opponentNameEl = $('opponent-name');
const opponentColorEl = $('opponent-color');
const selfNameEl = $('self-name');
const selfColorEl = $('self-color');
const opponentTurnDot = $('opponent-turn-indicator');
const selfTurnDot = $('self-turn-indicator');
const opponentCaptured = $('opponent-captured');
const playerCaptured = $('player-captured');
const opponentTimer = $('opponent-timer');
const selfTimer = $('self-timer');
const moveHistoryEl = $('move-history');
const chatMessages = $('chat-messages');
const chatInput = $('chat-input');
const btnSendChat = $('btn-send-chat');
const btnResign = $('btn-resign');
const btnOfferDraw = $('btn-offer-draw');
const gameoverModal = $('gameover-modal');
const gameoverIcon = $('gameover-icon');
const gameoverTitle = $('gameover-title');
const gameoverMessage = $('gameover-message');
const btnRematch = $('btn-rematch');
const btnNewGame = $('btn-new-game');
const rematchStatus = $('rematch-status');
const drawModal = $('draw-modal');
const btnAcceptDraw = $('btn-accept-draw');
const btnDeclineDraw = $('btn-decline-draw');
const resignModal = $('resign-modal');
const btnConfirmResign = $('btn-confirm-resign');
const btnCancelResign = $('btn-cancel-resign');
const promotionModal = $('promotion-modal');
const promotionPieces = $('promotion-pieces');

// ==========================================
// AUTH FLOW
// ==========================================

function hideAllAuthForms() {
    loginForm.classList.add('hidden');
    signupForm.classList.add('hidden');
    verifyForm.classList.add('hidden');
    forgotForm.classList.add('hidden');
}

function showAuthForm(form) {
    hideAllAuthForms();
    form.classList.remove('hidden');
}

// Helper: show email preview link or dev code
function showEmailResult(data, codeEl, codeDisplay, previewLinkEl, previewUrlEl) {
    if (codeDisplay) codeDisplay.classList.add('hidden');
    if (previewLinkEl) previewLinkEl.classList.add('hidden');

    if (data.devCode && codeEl && codeDisplay) {
        codeEl.textContent = data.devCode;
        codeDisplay.classList.remove('hidden');
    }
    if (data.previewUrl && previewLinkEl && previewUrlEl) {
        previewUrlEl.href = data.previewUrl;
        previewLinkEl.classList.remove('hidden');
    }
}

showSignup.addEventListener('click', (e) => { e.preventDefault(); showAuthForm(signupForm); signupError.classList.add('hidden'); });
showLogin.addEventListener('click', (e) => { e.preventDefault(); showAuthForm(loginForm); loginError.classList.add('hidden'); });
showForgot.addEventListener('click', (e) => { e.preventDefault(); showAuthForm(forgotForm); forgotError.classList.add('hidden'); forgotStep1.classList.remove('hidden'); forgotStep2.classList.add('hidden'); forgotDevCode.classList.add('hidden'); });
btnBackToLogin.addEventListener('click', () => { showAuthForm(loginForm); });
btnBackFromForgot.addEventListener('click', () => { showAuthForm(loginForm); });

// Password Strength
signupPassword.addEventListener('input', () => {
    const pw = signupPassword.value;
    const hasUpper = /[A-Z]/.test(pw);
    const hasLower = /[a-z]/.test(pw);
    const hasNum = /[0-9]/.test(pw);
    const hasLen = pw.length >= 6;
    const score = [hasUpper, hasLower, hasNum, hasLen].filter(Boolean).length;

    passwordStrength.innerHTML = '';
    for (let i = 0; i < 4; i++) {
        const bar = document.createElement('div');
        bar.className = 'bar';
        if (i < score) {
            bar.classList.add(score <= 1 ? 'weak' : score <= 2 ? 'medium' : score <= 3 ? 'medium' : 'strong');
        }
        passwordStrength.appendChild(bar);
    }
});

// ---- SIGNUP ----
btnSignup.addEventListener('click', async () => {
    signupError.classList.add('hidden');
    const username = signupUsername.value.trim();
    const email = signupEmail.value.trim();
    const password = signupPassword.value;

    if (!username || !email || !password) {
        signupError.textContent = 'All fields are required.';
        signupError.classList.remove('hidden');
        return;
    }

    btnSignup.disabled = true;
    btnSignup.textContent = 'Creating...';

    try {
        const res = await fetch('/api/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });
        const data = await res.json();
        btnSignup.disabled = false;
        btnSignup.textContent = 'CREATE ACCOUNT';

        if (!res.ok) {
            signupError.textContent = data.error;
            signupError.classList.remove('hidden');
            return;
        }

        if (data.requiresVerification) {
            pendingVerifyEmail = data.email;
            verifyEmailDisplay.textContent = data.email;
            showAuthForm(verifyForm);
            showEmailResult(data, devCodeValue, devCodeDisplay, $('email-preview-link'), $('email-preview-url'));
        }
    } catch (e) {
        btnSignup.disabled = false;
        btnSignup.textContent = 'CREATE ACCOUNT';
        signupError.textContent = 'Connection error.';
        signupError.classList.remove('hidden');
    }
});

// ---- VERIFY EMAIL ----
btnVerify.addEventListener('click', async () => {
    verifyError.classList.add('hidden');
    const code = verifyCode.value.trim();
    if (!code || code.length !== 6) {
        verifyError.textContent = 'Enter the 6-digit code.';
        verifyError.classList.remove('hidden');
        return;
    }

    btnVerify.disabled = true;
    try {
        const res = await fetch('/api/verify-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: pendingVerifyEmail, code })
        });
        const data = await res.json();
        btnVerify.disabled = false;

        if (!res.ok) {
            verifyError.textContent = data.error;
            verifyError.classList.remove('hidden');
            return;
        }

        currentUser = data.user;
        localStorage.setItem('chess-user', JSON.stringify({ email: currentUser.email }));
        enterApp();
    } catch (e) {
        btnVerify.disabled = false;
        verifyError.textContent = 'Connection error.';
        verifyError.classList.remove('hidden');
    }
});

verifyCode.addEventListener('keydown', (e) => { if (e.key === 'Enter') btnVerify.click(); });

// ---- RESEND CODE ----
btnResendCode.addEventListener('click', async () => {
    btnResendCode.disabled = true;
    btnResendCode.textContent = 'Sending...';
    try {
        const res = await fetch('/api/resend-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: pendingVerifyEmail })
        });
        const data = await res.json();
        btnResendCode.disabled = false;
        btnResendCode.textContent = 'RESEND CODE';

        if (data.devCode) {
            devCodeValue.textContent = data.devCode;
            devCodeDisplay.classList.remove('hidden');
        }
        showEmailResult(data, devCodeValue, devCodeDisplay, $('email-preview-link'), $('email-preview-url'));
    } catch (e) {
        btnResendCode.disabled = false;
        btnResendCode.textContent = 'RESEND CODE';
    }
});

// ---- LOGIN ----
btnLogin.addEventListener('click', async () => {
    loginError.classList.add('hidden');
    const email = loginEmail.value.trim();
    const password = loginPassword.value;

    if (!email || !password) {
        loginError.textContent = 'Enter email and password.';
        loginError.classList.remove('hidden');
        return;
    }

    btnLogin.disabled = true;
    btnLogin.textContent = 'Signing in...';

    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        btnLogin.disabled = false;
        btnLogin.textContent = 'SIGN IN';

        if (data.requiresVerification) {
            pendingVerifyEmail = data.email;
            verifyEmailDisplay.textContent = data.email;
            showAuthForm(verifyForm);
            showEmailResult(data, devCodeValue, devCodeDisplay, $('email-preview-link'), $('email-preview-url'));
            return;
        }

        if (!res.ok) {
            loginError.textContent = data.error;
            loginError.classList.remove('hidden');
            return;
        }

        currentUser = data.user;
        localStorage.setItem('chess-user', JSON.stringify({ email: currentUser.email }));
        enterApp();
    } catch (e) {
        btnLogin.disabled = false;
        btnLogin.textContent = 'SIGN IN';
        loginError.textContent = 'Connection error.';
        loginError.classList.remove('hidden');
    }
});

loginPassword.addEventListener('keydown', (e) => { if (e.key === 'Enter') btnLogin.click(); });

// ---- FORGOT PASSWORD ----
btnSendReset.addEventListener('click', async () => {
    forgotError.classList.add('hidden');
    const email = forgotEmail.value.trim();
    if (!email) {
        forgotError.textContent = 'Enter your email.';
        forgotError.classList.remove('hidden');
        return;
    }

    btnSendReset.disabled = true;
    try {
        const res = await fetch('/api/forgot-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();
        btnSendReset.disabled = false;

        if (data.devCode) {
            forgotDevCodeValue.textContent = data.devCode;
            forgotDevCode.classList.remove('hidden');
        }
        showEmailResult(data, forgotDevCodeValue, forgotDevCode, $('forgot-preview-link'), $('forgot-preview-url'));

        forgotStep1.classList.add('hidden');
        forgotStep2.classList.remove('hidden');
        $('forgot-subtitle').textContent = 'Enter the reset code and your new password.';
    } catch (e) {
        btnSendReset.disabled = false;
        forgotError.textContent = 'Connection error.';
        forgotError.classList.remove('hidden');
    }
});

btnResetPassword.addEventListener('click', async () => {
    resetError.classList.add('hidden');
    const code = resetCode.value.trim();
    const pw = newPassword.value;
    const cpw = confirmPassword.value;

    if (!code || code.length !== 6) {
        resetError.textContent = 'Enter the 6-digit code.';
        resetError.classList.remove('hidden');
        return;
    }
    if (pw !== cpw) {
        resetError.textContent = 'Passwords do not match.';
        resetError.classList.remove('hidden');
        return;
    }

    btnResetPassword.disabled = true;
    try {
        const res = await fetch('/api/reset-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: forgotEmail.value.trim(), code, newPassword: pw })
        });
        const data = await res.json();
        btnResetPassword.disabled = false;

        if (!res.ok) {
            resetError.textContent = data.error;
            resetError.classList.remove('hidden');
            return;
        }

        // Success — go back to login
        showAuthForm(loginForm);
        loginError.textContent = ''; // Clear
        loginEmail.value = forgotEmail.value;
        // Show success message
        const successDiv = document.createElement('div');
        successDiv.style.cssText = 'margin-top:12px;padding:10px 14px;background:rgba(52,211,153,0.1);border:1px solid rgba(52,211,153,0.3);border-radius:8px;color:#34d399;font-size:13px;text-align:center;';
        successDiv.textContent = 'Password reset successfully! Sign in with your new password.';
        loginForm.insertBefore(successDiv, loginForm.querySelector('.auth-links'));
        setTimeout(() => successDiv.remove(), 5000);
    } catch (e) {
        btnResetPassword.disabled = false;
        resetError.textContent = 'Connection error.';
        resetError.classList.remove('hidden');
    }
});

// ---- GOOGLE SIGN-IN ----
let googleClientId = null;

async function initGoogleAuth() {
    try {
        const res = await fetch('/api/config');
        const config = await res.json();
        googleClientId = config.googleClientId;

        if (googleClientId) {
            // Load Google Identity Services
            const script = document.createElement('script');
            script.src = 'https://accounts.google.com/gsi/client';
            script.onload = () => {
                window.google.accounts.id.initialize({
                    client_id: googleClientId,
                    callback: handleGoogleCredential
                });
            };
            document.head.appendChild(script);
        } else {
            // Hide Google buttons if not configured
            btnGoogleSignin.style.opacity = '0.5';
            btnGoogleSignin.title = 'Google Sign-In not configured';
            btnGoogleSignup.style.opacity = '0.5';
            btnGoogleSignup.title = 'Google Sign-In not configured';
        }
    } catch (e) {
        console.warn('Failed to load Google config');
    }
}

function triggerGooglePopup() {
    if (!googleClientId || !window.google) {
        alert('Google Sign-In is not configured.\nSet GOOGLE_CLIENT_ID in .env to enable it.');
        return;
    }
    window.google.accounts.id.prompt();
}

btnGoogleSignin.addEventListener('click', triggerGooglePopup);
btnGoogleSignup.addEventListener('click', triggerGooglePopup);

async function handleGoogleCredential(response) {
    try {
        const res = await fetch('/api/google-login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credential: response.credential })
        });
        const data = await res.json();

        if (!res.ok) {
            loginError.textContent = data.error;
            loginError.classList.remove('hidden');
            return;
        }

        currentUser = data.user;
        localStorage.setItem('chess-user', JSON.stringify({ email: currentUser.email }));
        enterApp();
    } catch (e) {
        loginError.textContent = 'Google sign-in failed.';
        loginError.classList.remove('hidden');
    }
}

// Make available globally for Google callback
window.handleGoogleLogin = handleGoogleCredential;

// ---- GUEST ----
btnGuest.addEventListener('click', () => {
    currentUser = { username: 'Guest', email: null, stats: { wins: 0, losses: 0, draws: 0, gamesPlayed: 0 }, gameHistory: [], verified: false, googleUser: false };
    enterApp();
});

// ---- LOGOUT ----
btnLogout.addEventListener('click', () => {
    currentUser = null;
    localStorage.removeItem('chess-user');
    authScreen.classList.add('active');
    mainApp.classList.remove('active');
    showAuthForm(loginForm);
});

// ---- Enter App ----
function enterApp() {
    authScreen.classList.remove('active');
    mainApp.classList.add('active');
    navUsername.textContent = currentUser.username || 'Guest';

    // Verified badge
    if (currentUser.verified) {
        verifiedBadge.classList.remove('hidden');
    } else {
        verifiedBadge.classList.add('hidden');
    }

    updateProfile();
    updateGameHistory();
}

// Auto-login
async function tryAutoLogin() {
    const saved = localStorage.getItem('chess-user');
    if (saved) {
        try {
            const { email } = JSON.parse(saved);
            if (email) {
                const res = await fetch(`/api/profile/${encodeURIComponent(email)}`);
                if (res.ok) {
                    currentUser = await res.json();
                    if (currentUser.verified) {
                        enterApp();
                        return;
                    }
                }
            }
        } catch (e) { /* ignore */ }
        localStorage.removeItem('chess-user');
    }
}

// ==========================================
// TAB NAVIGATION
// ==========================================
document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        $(`tab-${tab.dataset.tab}`)?.classList.add('active');
        if (tab.dataset.tab === 'profile') updateProfile();
        if (tab.dataset.tab === 'history') updateGameHistory();
    });
});

// ==========================================
// TIME CONTROL
// ==========================================
document.querySelectorAll('.time-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.time-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        selectedTimeControl = btn.dataset.time;
    });
});

// ==========================================
// CHESS.JS
// ==========================================
function loadChessJS() {
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/chess.js/0.10.3/chess.min.js';
        script.onload = () => { chess = new Chess(); resolve(); };
        script.onerror = reject;
        document.head.appendChild(script);
    });
}

// ==========================================
// SCREEN MANAGEMENT
// ==========================================
function showSubScreen(screen) {
    [lobbyScreen, waitingScreen, gameScreen].forEach(s => s.classList.remove('active'));
    screen.classList.add('active');
}

// ==========================================
// BOARD RENDERING
// ==========================================
function renderBoard() {
    chessBoard.innerHTML = '';
    const board = chess.board();
    const isFlipped = myColor === 'black';

    for (let row = 0; row < 8; row++) {
        for (let col = 0; col < 8; col++) {
            const r = isFlipped ? 7 - row : row;
            const c = isFlipped ? 7 - col : col;
            const file = 'abcdefgh'[c];
            const rank = 8 - r;
            const squareName = file + rank;
            const isLight = (r + c) % 2 === 0;

            const sq = document.createElement('div');
            sq.className = `square ${isLight ? 'light' : 'dark'}`;
            sq.dataset.square = squareName;

            if (lastMove && (squareName === lastMove.from || squareName === lastMove.to)) sq.classList.add('last-move');
            if (selectedSquare === squareName) sq.classList.add('selected');
            if (legalMoves.includes(squareName)) {
                const p = chess.get(squareName);
                sq.classList.add(p ? 'legal-capture' : 'legal-move');
            }
            if (chess.in_check()) {
                const piece = board[r][c];
                if (piece && piece.type === 'k' && piece.color === chess.turn()) sq.classList.add('in-check');
            }

            const piece = board[r][c];
            if (piece) {
                const span = document.createElement('span');
                span.className = `piece ${piece.color === 'w' ? 'white-piece' : 'black-piece'}`;
                span.textContent = PIECE_UNICODE[piece.color + piece.type] || '';
                sq.appendChild(span);
            }

            if (col === 0) { const l = document.createElement('span'); l.className = 'coord-label coord-rank'; l.textContent = rank; sq.appendChild(l); }
            if (row === 7) { const l = document.createElement('span'); l.className = 'coord-label coord-file'; l.textContent = file; sq.appendChild(l); }

            sq.addEventListener('click', () => handleSquareClick(squareName));
            chessBoard.appendChild(sq);
        }
    }
}

// ==========================================
// SQUARE CLICK + MOVE LOGIC
// ==========================================
function handleSquareClick(squareName) {
    if (!gameActive) return;
    const turn = chess.turn() === 'w' ? 'white' : 'black';
    if (turn !== myColor) return;

    if (selectedSquare) {
        if (squareName === selectedSquare) { selectedSquare = null; legalMoves = []; renderBoard(); return; }
        if (legalMoves.includes(squareName)) {
            const piece = chess.get(selectedSquare);
            const targetRank = squareName[1];
            if (piece && piece.type === 'p' && (targetRank === '8' || targetRank === '1')) { showPromotionModal(selectedSquare, squareName); return; }
            makeMove(selectedSquare, squareName); return;
        }
        const clicked = chess.get(squareName);
        if (clicked && clicked.color === chess.turn()) { selectSquare(squareName); return; }
        selectedSquare = null; legalMoves = []; renderBoard(); return;
    }
    const piece = chess.get(squareName);
    if (piece && piece.color === chess.turn()) selectSquare(squareName);
}

function selectSquare(sq) {
    selectedSquare = sq;
    legalMoves = chess.moves({ square: sq, verbose: true }).map(m => m.to);
    renderBoard();
}

function makeMove(from, to, promotion) {
    socket.emit('make-move', { from, to, promotion: promotion || undefined });
    selectedSquare = null; legalMoves = [];
}

function showPromotionModal(from, to) {
    promotionPieces.innerHTML = '';
    const color = myColor === 'white' ? 'w' : 'b';
    ['q', 'r', 'b', 'n'].forEach(type => {
        const btn = document.createElement('div');
        btn.className = 'promotion-piece';
        btn.textContent = PIECE_UNICODE[color + type];
        btn.addEventListener('click', () => { promotionModal.classList.add('hidden'); makeMove(from, to, type); });
        promotionPieces.appendChild(btn);
    });
    promotionModal.classList.remove('hidden');
}

// ==========================================
// TIMERS
// ==========================================
function formatTime(ms) {
    if (ms == null) return '--:--';
    const s = Math.max(0, Math.ceil(ms / 1000));
    return `${Math.floor(s / 60)}:${(s % 60).toString().padStart(2, '0')}`;
}

function updateTimerDisplay(timers) {
    if (!timers) { selfTimer.textContent = '--:--'; opponentTimer.textContent = '--:--'; selfTimer.className = 'chess-timer'; opponentTimer.className = 'chess-timer'; return; }
    const turn = chess.turn() === 'w' ? 'white' : 'black';
    const oppColor = myColor === 'white' ? 'black' : 'white';
    selfTimer.textContent = formatTime(timers[myColor]);
    opponentTimer.textContent = formatTime(timers[oppColor]);
    selfTimer.className = 'chess-timer';
    opponentTimer.className = 'chess-timer';
    if (gameActive) {
        if (turn === myColor) { selfTimer.classList.add('active-timer'); if (timers[myColor] <= 10000) selfTimer.classList.add('low-time'); }
        else { opponentTimer.classList.add('active-timer'); if (timers[oppColor] <= 10000) opponentTimer.classList.add('low-time'); }
    }
}

// ==========================================
// TURN, HISTORY, CAPTURED
// ==========================================
function updateTurnIndicators() {
    const turn = chess.turn() === 'w' ? 'white' : 'black';
    const iMyTurn = turn === myColor;
    selfTurnDot.classList.toggle('active', iMyTurn);
    opponentTurnDot.classList.toggle('active', !iMyTurn);
    if (chess.in_checkmate()) { statusText.textContent = `Checkmate!`; statusText.style.color = 'var(--danger)'; }
    else if (chess.in_check()) { statusText.textContent = `Check!`; statusText.style.color = 'var(--danger)'; }
    else if (chess.in_draw()) { statusText.textContent = 'Draw!'; statusText.style.color = 'var(--warning)'; }
    else { statusText.textContent = iMyTurn ? 'Your turn' : "Opponent's turn"; statusText.style.color = iMyTurn ? 'var(--success)' : 'var(--text-secondary)'; }
}

function updateMoveHistory(history) {
    moveHistoryEl.innerHTML = '';
    for (let i = 0; i < history.length; i += 2) {
        const row = document.createElement('div'); row.className = 'move-row';
        const num = document.createElement('span'); num.className = 'move-number'; num.textContent = (Math.floor(i / 2) + 1) + '.';
        const ws = document.createElement('span'); ws.className = 'move-white'; ws.textContent = history[i]; if (i === history.length - 1) ws.classList.add('latest');
        row.appendChild(num); row.appendChild(ws);
        if (history[i + 1]) { const bs = document.createElement('span'); bs.className = 'move-black'; bs.textContent = history[i + 1]; if (i + 1 === history.length - 1) bs.classList.add('latest'); row.appendChild(bs); }
        moveHistoryEl.appendChild(row);
    }
    moveHistoryEl.scrollTop = moveHistoryEl.scrollHeight;
}

function updateCapturedPieces() {
    const init = { p: 8, n: 2, b: 2, r: 2, q: 1 };
    const cur = { w: { p: 0, n: 0, b: 0, r: 0, q: 0 }, b: { p: 0, n: 0, b: 0, r: 0, q: 0 } };
    const board = chess.board();
    for (let r = 0; r < 8; r++) for (let c = 0; c < 8; c++) { const p = board[r][c]; if (p && p.type !== 'k') cur[p.color][p.type]++; }
    function build(clr) {
        let h = '';
        ['q', 'r', 'b', 'n', 'p'].forEach(t => { for (let i = 0; i < init[t] - cur[clr][t]; i++) h += `<span class="${clr === 'w' ? 'white-piece' : 'black-piece'}" style="filter:none;">${PIECE_UNICODE[clr + t]}</span>`; });
        return h;
    }
    if (myColor === 'white') { playerCaptured.innerHTML = build('b'); opponentCaptured.innerHTML = build('w'); }
    else { playerCaptured.innerHTML = build('w'); opponentCaptured.innerHTML = build('b'); }
}

// ==========================================
// SETUP GAME
// ==========================================
function setupGame(data) {
    myColor = data.color; gameActive = true; selectedSquare = null; legalMoves = []; lastMove = null;
    chess.load(data.fen);
    if (myColor === 'white') { selfNameEl.textContent = data.white; selfColorEl.textContent = 'White ♔'; opponentNameEl.textContent = data.black; opponentColorEl.textContent = 'Black ♚'; }
    else { selfNameEl.textContent = data.black; selfColorEl.textContent = 'Black ♚'; opponentNameEl.textContent = data.white; opponentColorEl.textContent = 'White ♔'; }
    updateTurnIndicators(); updateCapturedPieces(); updateMoveHistory([]); updateTimerDisplay(data.timers);
    renderBoard(); showSubScreen(gameScreen); playGameStartSound();
}

// ==========================================
// CHAT
// ==========================================
function addChatMessage(sender, color, text) {
    const msg = document.createElement('div'); msg.className = 'chat-msg';
    msg.innerHTML = `<span class="chat-sender ${color}-sender">${escapeHtml(sender)}:</span><span class="chat-text">${escapeHtml(text)}</span>`;
    chatMessages.appendChild(msg); chatMessages.scrollTop = chatMessages.scrollHeight;
}
function addSystemMessage(text) {
    const msg = document.createElement('div'); msg.className = 'chat-msg';
    msg.innerHTML = `<span class="chat-text" style="color:var(--text-muted);font-style:italic;">${text}</span>`;
    chatMessages.appendChild(msg); chatMessages.scrollTop = chatMessages.scrollHeight;
}
function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }

// ==========================================
// PROFILE + HISTORY
// ==========================================
function updateProfile() {
    if (!currentUser) return;
    $('profile-username').textContent = currentUser.username || 'Guest';
    $('profile-email').textContent = currentUser.email || 'Not signed in';
    $('stat-games').textContent = currentUser.stats?.gamesPlayed || 0;
    $('stat-wins').textContent = currentUser.stats?.wins || 0;
    $('stat-losses').textContent = currentUser.stats?.losses || 0;
    $('stat-draws').textContent = currentUser.stats?.draws || 0;
    const total = currentUser.stats?.gamesPlayed || 0;
    const wins = currentUser.stats?.wins || 0;
    const rate = total > 0 ? Math.round((wins / total) * 100) : 0;
    $('win-rate-fill').style.width = `${rate}%`;
    $('win-rate-text').textContent = `${rate}%`;

    // Badges
    const vb = $('profile-verified-badge');
    const gb = $('profile-google-badge');
    if (currentUser.verified) vb.classList.remove('hidden'); else vb.classList.add('hidden');
    if (currentUser.googleUser) gb.classList.remove('hidden'); else gb.classList.add('hidden');

    // Security card
    $('sec-email').textContent = currentUser.verified ? '✅ Verified' : '⚠️ Not verified';
    $('sec-email').style.color = currentUser.verified ? 'var(--success)' : 'var(--warning)';
    $('sec-auth').textContent = currentUser.googleUser ? '🔗 Google OAuth' : '🔐 Email + Password';
    $('sec-password').textContent = currentUser.googleUser ? 'N/A (Google)' : '🔐 Hashed (bcrypt)';
}

function updateGameHistory() {
    const list = $('history-list');
    const games = currentUser?.gameHistory || [];
    if (!games.length) {
        list.innerHTML = '<div class="empty-state glass-panel"><span class="empty-icon">📋</span><p>No games played yet</p><p class="text-muted">Your completed games will appear here</p></div>';
        return;
    }
    list.innerHTML = '';
    games.forEach(g => {
        const isW = g.white === currentUser.username;
        const r = g.result === 'draw' ? 'draw' : ((g.result === 'white' && isW) || (g.result === 'black' && !isW)) ? 'win' : 'loss';
        const d = new Date(g.date).toLocaleDateString();
        const tc = g.timeControl ? g.timeControl.charAt(0).toUpperCase() + g.timeControl.slice(1) : '';
        const item = document.createElement('div'); item.className = 'history-item';
        item.innerHTML = `<div class="history-result ${r}">${r === 'win' ? 'W' : r === 'loss' ? 'L' : '½'}</div><div class="history-details"><div class="history-players">${escapeHtml(g.white)} vs ${escapeHtml(g.black)}</div><div class="history-meta"><span>${d}</span><span>${tc}</span><span>${g.moves?.length || 0} moves</span></div></div>`;
        list.appendChild(item);
    });
}

// ==========================================
// PUZZLES (unchanged from before)
// ==========================================
const PUZZLES = [
    { fen: 'r1bqkb1r/pppp1ppp/2n2n2/4p2Q/2B1P3/8/PPPP1PPP/RNB1K1NR w KQkq - 4 4', solution: ['h5f7'], theme: "Scholar's Mate", rating: 800, instruction: 'White to move — find the checkmate!' },
    { fen: 'r1b1k2r/ppppqppp/2n2n2/2b1p3/2B1P3/2N2N2/PPPP1PPP/R1BQK2R w KQkq - 6 5', solution: ['f3e5'], theme: 'Fork', rating: 1000, instruction: 'White to move — win material!' },
    { fen: '6k1/5ppp/8/8/8/8/r4PPP/1R4K1 w - - 0 1', solution: ['b1b8'], theme: 'Back Rank', rating: 1100, instruction: 'White to move — back rank mate!' },
    { fen: 'r2qk2r/ppp2ppp/2n1bn2/2b1p3/4P3/1BN2N2/PPPP1PPP/R1BQ1RK1 w kq - 6 6', solution: ['f3e5'], theme: 'Center Control', rating: 1200, instruction: 'White to move — seize the center!' },
    { fen: '2r3k1/5ppp/p7/1p6/8/1P6/P4PPP/2R3K1 w - - 0 1', solution: ['c1c8'], theme: 'Back Rank', rating: 1000, instruction: 'White to move — back rank threat!' },
    { fen: 'r4rk1/ppp2ppp/2n5/3qp3/8/2NP1B2/PPP2PPP/R2Q1RK1 w - - 0 10', solution: ['f3d5'], theme: 'Pin & Win', rating: 1300, instruction: 'White to move — exploit the pin!' },
];

let currentPuzzleIndex = 0, puzzleChess = null, puzzleSelected = null, puzzleLegalMoves = [];

function loadPuzzle(idx) {
    currentPuzzleIndex = idx % PUZZLES.length;
    const p = PUZZLES[currentPuzzleIndex];
    puzzleChess = new Chess(p.fen); puzzleSelected = null; puzzleLegalMoves = [];
    $('puzzle-rating').textContent = p.rating; $('puzzle-theme').textContent = p.theme;
    $('puzzle-instruction').textContent = p.instruction; $('puzzle-feedback').classList.add('hidden');
    renderPuzzleBoard();
}

function renderPuzzleBoard() {
    const el = $('puzzle-board'); el.innerHTML = '';
    const board = puzzleChess.board();
    for (let row = 0; row < 8; row++) for (let col = 0; col < 8; col++) {
        const sq = document.createElement('div');
        sq.className = `square ${(row + col) % 2 === 0 ? 'light' : 'dark'}`;
        const sn = 'abcdefgh'[col] + (8 - row);
        sq.dataset.square = sn;
        if (puzzleSelected === sn) sq.classList.add('selected');
        if (puzzleLegalMoves.includes(sn)) { const pp = puzzleChess.get(sn); sq.classList.add(pp ? 'legal-capture' : 'legal-move'); }
        const piece = board[row][col];
        if (piece) { const s = document.createElement('span'); s.className = `piece ${piece.color === 'w' ? 'white-piece' : 'black-piece'}`; s.textContent = PIECE_UNICODE[piece.color + piece.type]; sq.appendChild(s); }
        sq.addEventListener('click', () => handlePuzzleClick(sn));
        el.appendChild(sq);
    }
}

function handlePuzzleClick(sn) {
    if (puzzleChess.game_over()) return;
    const turn = puzzleChess.turn();
    if (puzzleSelected) {
        if (sn === puzzleSelected) { puzzleSelected = null; puzzleLegalMoves = []; renderPuzzleBoard(); return; }
        if (puzzleLegalMoves.includes(sn)) {
            const ms = puzzleSelected + sn;
            try {
                const m = puzzleChess.move({ from: puzzleSelected, to: sn, promotion: 'q' });
                if (m) {
                    puzzleSelected = null; puzzleLegalMoves = []; renderPuzzleBoard();
                    const fb = $('puzzle-feedback');
                    if (PUZZLES[currentPuzzleIndex].solution.includes(ms)) { fb.textContent = '✓ Correct!'; fb.className = 'puzzle-feedback correct'; playGameStartSound(); }
                    else { fb.textContent = '✗ Not the best move.'; fb.className = 'puzzle-feedback wrong'; playCheckSound(); }
                    fb.classList.remove('hidden'); return;
                }
            } catch (e) { }
        }
        const cp = puzzleChess.get(sn);
        if (cp && cp.color === turn) { puzzleSelected = sn; puzzleLegalMoves = puzzleChess.moves({ square: sn, verbose: true }).map(m => m.to); renderPuzzleBoard(); return; }
        puzzleSelected = null; puzzleLegalMoves = []; renderPuzzleBoard(); return;
    }
    const p = puzzleChess.get(sn);
    if (p && p.color === turn) { puzzleSelected = sn; puzzleLegalMoves = puzzleChess.moves({ square: sn, verbose: true }).map(m => m.to); renderPuzzleBoard(); }
}

$('btn-puzzle-next').addEventListener('click', () => loadPuzzle(currentPuzzleIndex + 1));
$('btn-puzzle-hint').addEventListener('click', () => {
    const s = PUZZLES[currentPuzzleIndex].solution[0];
    if (s) { puzzleSelected = s.substring(0, 2); puzzleLegalMoves = puzzleChess.moves({ square: puzzleSelected, verbose: true }).map(m => m.to); renderPuzzleBoard(); }
});

// ==========================================
// SOCKET EVENT HANDLERS
// ==========================================
socket.on('game-created', (data) => { displayRoomCode.textContent = data.roomCode; gameRoomCode.textContent = data.roomCode; const labels = { bullet: 'Bullet • 1 min', blitz: 'Blitz • 3 min', rapid: 'Rapid • 10 min' }; waitingTimeLabel.textContent = labels[data.timeControl] || ''; showSubScreen(waitingScreen); });
socket.on('join-error', (msg) => { lobbyError.textContent = msg; lobbyError.classList.remove('hidden'); });
socket.on('game-joined', (data) => { gameRoomCode.textContent = data.roomCode; setupGame(data); addSystemMessage('Game started! Good luck!'); });
socket.on('opponent-joined', (data) => { setupGame(data); addSystemMessage('Opponent connected!'); });

socket.on('move-made', (data) => {
    chess.load(data.fen); lastMove = data.move; selectedSquare = null; legalMoves = [];
    if (data.isCheckmate) playCheckmateSound();
    else if (data.isCheck) playCheckSound();
    else if (data.move.flags && (data.move.flags.includes('k') || data.move.flags.includes('q'))) playCastleSound();
    else if (data.move.captured) playCaptureSound();
    else playMoveSound();
    renderBoard(); updateTurnIndicators(); updateCapturedPieces(); updateMoveHistory(data.history);
    if (data.timers) updateTimerDisplay(data.timers);
    if (data.isGameOver) {
        gameActive = false;
        let title, message, icon;
        if (data.isCheckmate) { const w = data.turn === 'w' ? 'Black' : 'White'; const iWon = w.toLowerCase() === myColor; title = iWon ? '🎉 You Win!' : 'You Lost'; message = `Checkmate! ${w} wins.`; icon = iWon ? '🏆' : '♚'; }
        else if (data.isStalemate) { title = 'Stalemate'; message = 'Draw by stalemate.'; icon = '🤝'; }
        else { title = 'Draw'; message = 'Game ended in a draw.'; icon = '🤝'; }
        showGameOverModal(title, message, icon); refreshProfile();
    }
});

socket.on('timer-update', (timers) => updateTimerDisplay(timers));
socket.on('move-error', (msg) => console.warn('Move error:', msg));

socket.on('game-over', (data) => {
    gameActive = false; let title, message, icon;
    if (data.reason === 'resignation') { const w = data.winner === myColor; title = w ? '🎉 You Win!' : 'You Lost'; message = w ? 'Opponent resigned.' : 'You resigned.'; icon = w ? '🏆' : '🏳️'; }
    else if (data.reason === 'disconnection') { const w = data.winner === myColor; title = w ? '🎉 You Win!' : 'Connection Lost'; message = w ? 'Opponent disconnected.' : 'You disconnected.'; icon = w ? '🏆' : '⚡'; }
    else if (data.reason === 'draw-agreement') { title = 'Draw'; message = 'Both players agreed to a draw.'; icon = '🤝'; }
    else if (data.reason === 'timeout') { const w = data.winner === myColor; title = w ? '🎉 You Win!' : "Time's Up!"; message = w ? 'Opponent ran out of time.' : 'You ran out of time.'; icon = w ? '🏆' : '⏱'; }
    showGameOverModal(title, message, icon); refreshProfile();
});

socket.on('draw-offered', () => drawModal.classList.remove('hidden'));
socket.on('draw-declined', () => addSystemMessage('Draw offer declined.'));
socket.on('rematch-requested', () => { rematchStatus.textContent = 'Opponent wants a rematch!'; rematchStatus.classList.remove('hidden'); });
socket.on('rematch-start', (data) => { gameoverModal.classList.add('hidden'); rematchStatus.classList.add('hidden'); chatMessages.innerHTML = ''; setupGame(data); addSystemMessage('Rematch! Colors swapped.'); });
socket.on('chat-message', (data) => addChatMessage(data.sender, data.color, data.message));

// ==========================================
// UI EVENT HANDLERS
// ==========================================
btnCreate.addEventListener('click', () => {
    lobbyError.classList.add('hidden');
    socket.emit('create-game', { playerName: currentUser?.username || 'Player', email: currentUser?.email || null, timeControl: selectedTimeControl });
});

btnJoin.addEventListener('click', () => {
    const code = roomCodeInput.value.trim();
    if (!code) { lobbyError.textContent = 'Enter a room code.'; lobbyError.classList.remove('hidden'); return; }
    lobbyError.classList.add('hidden');
    socket.emit('join-game', { roomCode: code, playerName: currentUser?.username || 'Player', email: currentUser?.email || null });
});

roomCodeInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') btnJoin.click(); });
btnCopyCode.addEventListener('click', () => { navigator.clipboard.writeText(displayRoomCode.textContent).then(() => { btnCopyCode.textContent = '✓'; setTimeout(() => btnCopyCode.textContent = '📋', 1500); }); });
btnCancelWait.addEventListener('click', () => location.reload());

btnSendChat.addEventListener('click', sendChat);
chatInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendChat(); });
function sendChat() { const msg = chatInput.value.trim(); if (!msg) return; socket.emit('chat-message', msg); chatInput.value = ''; }

btnResign.addEventListener('click', () => resignModal.classList.remove('hidden'));
btnConfirmResign.addEventListener('click', () => { resignModal.classList.add('hidden'); socket.emit('resign'); });
btnCancelResign.addEventListener('click', () => resignModal.classList.add('hidden'));
btnOfferDraw.addEventListener('click', () => { socket.emit('offer-draw'); addSystemMessage('Draw offer sent...'); });
btnAcceptDraw.addEventListener('click', () => { drawModal.classList.add('hidden'); socket.emit('accept-draw'); });
btnDeclineDraw.addEventListener('click', () => { drawModal.classList.add('hidden'); socket.emit('decline-draw'); });

function showGameOverModal(title, message, icon) {
    gameoverTitle.textContent = title; gameoverMessage.textContent = message; gameoverIcon.textContent = icon || '♔';
    rematchStatus.classList.add('hidden'); btnRematch.disabled = false; gameoverModal.classList.remove('hidden');
}
btnRematch.addEventListener('click', () => { socket.emit('request-rematch'); rematchStatus.textContent = 'Waiting for opponent...'; rematchStatus.classList.remove('hidden'); btnRematch.disabled = true; });
btnNewGame.addEventListener('click', () => location.reload());

async function refreshProfile() {
    if (currentUser?.email) {
        try { const r = await fetch(`/api/profile/${encodeURIComponent(currentUser.email)}`); if (r.ok) { currentUser = await r.json(); updateProfile(); updateGameHistory(); } } catch (e) { }
    }
}

// ==========================================
// INIT
// ==========================================
loadChessJS().then(() => {
    console.log('♔ Chess Arena ready');
    tryAutoLogin();
    initGoogleAuth();
    loadPuzzle(0);
}).catch(err => console.error('Failed to load chess.js:', err));
