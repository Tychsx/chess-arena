require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Chess } = require('chess.js');
const path = require('path');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// ============ Security Middleware ============
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://accounts.google.com", "https://cdnjs.cloudflare.com", "https://apis.google.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://accounts.google.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://accounts.google.com", "wss:", "ws:"],
            frameSrc: ["https://accounts.google.com"],
        }
    }
}));

app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiters
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20,
    message: { error: 'Too many attempts. Please try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false
});

const verifyLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    message: { error: 'Too many verification attempts. Please try again later.' }
});

// ============ In-Memory Storage ============
const users = new Map();            // email -> user object
const verificationCodes = new Map(); // email -> { code, expiresAt, attempts }
const resetCodes = new Map();        // email -> { code, expiresAt, attempts }
const games = new Map();
const activeTimers = new Map();

// ============ Email Transporter ============
let transporter = null;
let emailFrom = '"Chess Arena" <noreply@chessarena.com>';
const SMTP_CONFIGURED = process.env.SMTP_USER && process.env.SMTP_PASS &&
    process.env.SMTP_USER !== 'your-email@gmail.com';

async function initEmailTransporter() {
    if (SMTP_CONFIGURED) {
        transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.SMTP_PORT || '587'),
            secure: false,
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        });
        emailFrom = `"Chess Arena" <${process.env.SMTP_USER}>`;
        try {
            await transporter.verify();
            console.log('📧 Email transporter ready (Gmail SMTP)');
        } catch (err) {
            console.warn('⚠️  Gmail SMTP failed:', err.message);
            console.log('📧 Falling back to Ethereal test email...');
            await setupEtherealTransporter();
        }
    } else {
        await setupEtherealTransporter();
    }
}

async function setupEtherealTransporter() {
    try {
        const testAccount = await nodemailer.createTestAccount();
        transporter = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            secure: false,
            auth: { user: testAccount.user, pass: testAccount.pass }
        });
        emailFrom = `"Chess Arena" <${testAccount.user}>`;
        console.log('📧 Ethereal test email ready — emails will be sent and viewable online!');
        console.log(`   Ethereal inbox: https://ethereal.email/login`);
        console.log(`   Login: ${testAccount.user} / ${testAccount.pass}`);
    } catch (err) {
        console.error('❌ Failed to create email transporter:', err.message);
    }
}

// Initialize email on startup
initEmailTransporter();

// Google Auth
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
let googleClient = null;
if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_ID !== 'your-google-client-id.apps.googleusercontent.com') {
    const { OAuth2Client } = require('google-auth-library');
    googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
    console.log('🔑 Google Sign-In configured');
} else {
    console.log('🔑 Google Sign-In not configured — set GOOGLE_CLIENT_ID in .env');
}

// ============ Helpers ============
function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateRoomCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 6; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
    return code;
}

function sanitizeInput(str, maxLen = 100) {
    if (typeof str !== 'string') return '';
    return str.trim().substring(0, maxLen).replace(/[<>]/g, '');
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongPassword(password) {
    // At least 6 chars, 1 uppercase, 1 lowercase, 1 number
    return password.length >= 6 &&
        /[A-Z]/.test(password) &&
        /[a-z]/.test(password) &&
        /[0-9]/.test(password);
}

async function sendEmail(to, subject, html) {
    if (!transporter) return { sent: false };
    try {
        const info = await transporter.sendMail({ from: emailFrom, to, subject, html });
        const previewUrl = nodemailer.getTestMessageUrl(info);
        if (previewUrl) {
            console.log(`📧 Email sent to ${to} — Preview: ${previewUrl}`);
        } else {
            console.log(`📧 Email sent to ${to} via SMTP`);
        }
        return { sent: true, previewUrl: previewUrl || null };
    } catch (err) {
        console.error('Email send error:', err.message);
        return { sent: false };
    }
}

function getPublicUser(user) {
    return {
        email: user.email,
        username: user.username,
        stats: user.stats,
        gameHistory: user.gameHistory,
        verified: user.verified,
        googleUser: user.googleUser || false
    };
}

function saveGameToHistory(game, result) {
    const record = {
        date: new Date().toISOString(),
        white: game.players.white.name,
        black: game.players.black?.name || 'Unknown',
        result,
        moves: game.chess.history(),
        timeControl: game.timeControl,
        pgn: game.chess.pgn()
    };

    [game.players.white, game.players.black].forEach(player => {
        if (player?.email) {
            const user = users.get(player.email);
            if (user) {
                user.gameHistory.unshift(record);
                if (user.gameHistory.length > 50) user.gameHistory.pop();
                user.stats.gamesPlayed++;
                if (result === 'draw') user.stats.draws++;
                else {
                    const playerColor = player === game.players.white ? 'white' : 'black';
                    if (result === playerColor) user.stats.wins++;
                    else user.stats.losses++;
                }
            }
        }
    });
}

// ============ Timer Helpers ============
function getTimeMs(tc) {
    switch (tc) {
        case 'bullet': return 60000;
        case 'blitz': return 180000;
        case 'rapid': return 600000;
        default: return null;
    }
}

function startTimer(roomCode) {
    const game = games.get(roomCode);
    if (!game || !game.timers) return;
    clearTimer(roomCode);
    game.lastTickTime = Date.now();
    const interval = setInterval(() => {
        if (game.status !== 'playing') { clearTimer(roomCode); return; }
        const now = Date.now();
        const elapsed = now - game.lastTickTime;
        game.lastTickTime = now;
        const currentTurn = game.chess.turn() === 'w' ? 'white' : 'black';
        game.timers[currentTurn] -= elapsed;
        if (game.timers[currentTurn] <= 0) {
            game.timers[currentTurn] = 0;
            game.status = 'finished';
            const winner = currentTurn === 'white' ? 'black' : 'white';
            saveGameToHistory(game, winner);
            io.to(roomCode).emit('game-over', { reason: 'timeout', winner, winnerName: game.players[winner]?.name || 'Opponent' });
            io.to(roomCode).emit('timer-update', { white: game.timers.white, black: game.timers.black });
            clearTimer(roomCode);
        } else {
            io.to(roomCode).emit('timer-update', { white: game.timers.white, black: game.timers.black });
        }
    }, 200);
    activeTimers.set(roomCode, interval);
}

function clearTimer(roomCode) {
    const i = activeTimers.get(roomCode);
    if (i) { clearInterval(i); activeTimers.delete(roomCode); }
}

// ============================================
// AUTH ROUTES
// ============================================

// ---- SIGNUP ----
app.post('/api/signup', authLimiter, async (req, res) => {
    try {
        const email = sanitizeInput(req.body.email, 100).toLowerCase();
        const username = sanitizeInput(req.body.username, 20);
        const password = req.body.password || '';

        if (!email || !username || !password) {
            return res.status(400).json({ error: 'All fields are required.' });
        }
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Invalid email address.' });
        }
        if (username.length < 2) {
            return res.status(400).json({ error: 'Username must be at least 2 characters.' });
        }
        if (!isStrongPassword(password)) {
            return res.status(400).json({ error: 'Password must be at least 6 characters with 1 uppercase, 1 lowercase, and 1 number.' });
        }
        if (users.has(email)) {
            return res.status(400).json({ error: 'An account with this email already exists.' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create user (unverified)
        const user = {
            email,
            username,
            password: hashedPassword,
            verified: false,
            googleUser: false,
            stats: { wins: 0, losses: 0, draws: 0, gamesPlayed: 0 },
            gameHistory: [],
            createdAt: new Date().toISOString()
        };
        users.set(email, user);

        // Generate verification code
        const code = generateCode();
        verificationCodes.set(email, {
            code,
            expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
            attempts: 0
        });

        // Send email or show in console
        const emailSent = await sendEmail(email, 'Chess Arena — Verify Your Email', `
      <div style="font-family:Arial,sans-serif;max-width:460px;margin:0 auto;padding:32px;background:#12121a;color:#e8e8f0;border-radius:12px;">
        <h2 style="text-align:center;color:#a88bfa;">♔ Chess Arena</h2>
        <p>Hi <strong>${username}</strong>,</p>
        <p>Your verification code is:</p>
        <div style="text-align:center;margin:24px 0;">
          <span style="font-size:36px;font-weight:800;letter-spacing:8px;color:#a88bfa;font-family:monospace;">${code}</span>
        </div>
        <p style="color:#8888a8;font-size:13px;">This code expires in 10 minutes. If you didn't create an account, ignore this email.</p>
      </div>
    `);

        const response = { success: true, message: 'Account created! Check your email for a verification code.', requiresVerification: true, email };

        if (!emailSent.sent) {
            console.log(`\n📧 Verification code for ${email}: ${code}\n`);
            response.devCode = code;
            response.message = 'Account created! (Email failed — code shown below)';
        } else if (emailSent.previewUrl) {
            response.previewUrl = emailSent.previewUrl;
            response.message = 'Account created! Verification email sent — click the link below to view it.';
        }

        res.json(response);
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ error: 'Server error. Please try again.' });
    }
});

// ---- VERIFY EMAIL ----
app.post('/api/verify-email', verifyLimiter, (req, res) => {
    const email = sanitizeInput(req.body.email, 100).toLowerCase();
    const code = sanitizeInput(req.body.code, 6);

    const stored = verificationCodes.get(email);
    if (!stored) {
        return res.status(400).json({ error: 'No verification pending for this email.' });
    }

    if (stored.attempts >= 5) {
        verificationCodes.delete(email);
        return res.status(400).json({ error: 'Too many failed attempts. Please sign up again.' });
    }

    if (Date.now() > stored.expiresAt) {
        verificationCodes.delete(email);
        return res.status(400).json({ error: 'Verification code expired. Please sign up again.' });
    }

    if (stored.code !== code) {
        stored.attempts++;
        return res.status(400).json({ error: `Incorrect code. ${5 - stored.attempts} attempts remaining.` });
    }

    // Verify user
    const user = users.get(email);
    if (!user) {
        return res.status(400).json({ error: 'User not found.' });
    }

    user.verified = true;
    verificationCodes.delete(email);

    res.json({ success: true, user: getPublicUser(user) });
});

// ---- RESEND VERIFICATION CODE ----
app.post('/api/resend-code', verifyLimiter, async (req, res) => {
    const email = sanitizeInput(req.body.email, 100).toLowerCase();
    const user = users.get(email);

    if (!user) return res.status(400).json({ error: 'No account found with this email.' });
    if (user.verified) return res.status(400).json({ error: 'Email already verified.' });

    const code = generateCode();
    verificationCodes.set(email, {
        code,
        expiresAt: Date.now() + 10 * 60 * 1000,
        attempts: 0
    });

    const emailSent = await sendEmail(email, 'Chess Arena — New Verification Code', `
    <div style="font-family:Arial,sans-serif;max-width:460px;margin:0 auto;padding:32px;background:#12121a;color:#e8e8f0;border-radius:12px;">
      <h2 style="text-align:center;color:#a88bfa;">♔ Chess Arena</h2>
      <p>Your new verification code is:</p>
      <div style="text-align:center;margin:24px 0;">
        <span style="font-size:36px;font-weight:800;letter-spacing:8px;color:#a88bfa;font-family:monospace;">${code}</span>
      </div>
      <p style="color:#8888a8;font-size:13px;">This code expires in 10 minutes.</p>
    </div>
  `);

    const response = { success: true, message: 'New verification code sent to your email!' };
    if (!emailSent.sent) {
        console.log(`\n📧 New verification code for ${email}: ${code}\n`);
        response.devCode = code;
        response.message = 'Code generated (email failed — shown below)';
    } else if (emailSent.previewUrl) {
        response.previewUrl = emailSent.previewUrl;
    }
    res.json(response);
});

// ---- LOGIN ----
app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const email = sanitizeInput(req.body.email, 100).toLowerCase();
        const password = req.body.password || '';

        const user = users.get(email);
        if (!user) {
            // Constant-time-ish response to prevent user enumeration
            await bcrypt.hash('dummy', 10);
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        if (user.googleUser && !user.password) {
            return res.status(401).json({ error: 'This account uses Google Sign-In. Please use the Google button.' });
        }

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        if (!user.verified) {
            // Resend verification code
            const code = generateCode();
            verificationCodes.set(email, { code, expiresAt: Date.now() + 10 * 60 * 1000, attempts: 0 });

            const emailSent = await sendEmail(email, 'Chess Arena — Verify Your Email', `
        <div style="font-family:Arial,sans-serif;max-width:460px;margin:0 auto;padding:32px;background:#12121a;color:#e8e8f0;border-radius:12px;">
          <h2 style="text-align:center;color:#a88bfa;">♔ Chess Arena</h2>
          <p>Your verification code is:</p>
          <div style="text-align:center;margin:24px 0;">
            <span style="font-size:36px;font-weight:800;letter-spacing:8px;color:#a88bfa;font-family:monospace;">${code}</span>
          </div>
          <p style="color:#8888a8;font-size:13px;">This code expires in 10 minutes.</p>
        </div>
      `);

            const response = { requiresVerification: true, email, message: 'Please verify your email first. A new code has been sent.' };
            if (!emailSent.sent) {
                console.log(`\n📧 Verification code for ${email}: ${code}\n`);
                response.devCode = code;
            } else if (emailSent.previewUrl) {
                response.previewUrl = emailSent.previewUrl;
            }
            return res.status(403).json(response);
        }

        res.json({ success: true, user: getPublicUser(user) });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error. Please try again.' });
    }
});

// ---- GOOGLE SIGN-IN ----
app.post('/api/google-login', authLimiter, async (req, res) => {
    if (!googleClient) {
        return res.status(501).json({ error: 'Google Sign-In is not configured on the server.' });
    }

    try {
        const { credential } = req.body;
        const ticket = await googleClient.verifyIdToken({
            idToken: credential,
            audience: GOOGLE_CLIENT_ID
        });
        const payload = ticket.getPayload();
        const email = payload.email.toLowerCase();
        const username = payload.name || payload.given_name || email.split('@')[0];

        let user = users.get(email);
        if (!user) {
            // Auto-create account for Google users
            user = {
                email,
                username: sanitizeInput(username, 20),
                password: null,
                verified: true, // Google users are auto-verified
                googleUser: true,
                stats: { wins: 0, losses: 0, draws: 0, gamesPlayed: 0 },
                gameHistory: [],
                createdAt: new Date().toISOString()
            };
            users.set(email, user);
            console.log(`New Google user: ${email}`);
        }

        if (!user.verified) user.verified = true;

        res.json({ success: true, user: getPublicUser(user) });
    } catch (err) {
        console.error('Google auth error:', err.message);
        res.status(401).json({ error: 'Google authentication failed. Please try again.' });
    }
});

// ---- FORGOT PASSWORD ----
app.post('/api/forgot-password', authLimiter, async (req, res) => {
    const email = sanitizeInput(req.body.email, 100).toLowerCase();

    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Invalid email address.' });
    }

    const user = users.get(email);
    // Always return success to prevent email enumeration
    const successResponse = { success: true, message: 'If an account exists with this email, a reset code has been sent.', email };

    if (!user) {
        return res.json(successResponse);
    }

    if (user.googleUser && !user.password) {
        return res.json({ success: true, message: 'This account uses Google Sign-In. No password to reset.' });
    }

    const code = generateCode();
    resetCodes.set(email, {
        code,
        expiresAt: Date.now() + 10 * 60 * 1000,
        attempts: 0
    });

    const emailSent = await sendEmail(email, 'Chess Arena — Password Reset', `
    <div style="font-family:Arial,sans-serif;max-width:460px;margin:0 auto;padding:32px;background:#12121a;color:#e8e8f0;border-radius:12px;">
      <h2 style="text-align:center;color:#a88bfa;">♔ Chess Arena</h2>
      <p>Hi <strong>${user.username}</strong>,</p>
      <p>Your password reset code is:</p>
      <div style="text-align:center;margin:24px 0;">
        <span style="font-size:36px;font-weight:800;letter-spacing:8px;color:#a88bfa;font-family:monospace;">${code}</span>
      </div>
      <p style="color:#8888a8;font-size:13px;">This code expires in 10 minutes. If you didn't request a reset, ignore this email.</p>
    </div>
  `);

    if (!emailSent.sent) {
        console.log(`\n🔑 Password reset code for ${email}: ${code}\n`);
        successResponse.devCode = code;
        successResponse.message = 'Reset code generated (email failed — shown below)';
    } else if (emailSent.previewUrl) {
        successResponse.previewUrl = emailSent.previewUrl;
        successResponse.message = 'Password reset email sent! Click the link below to view it.';
    }

    res.json(successResponse);
});

// ---- RESET PASSWORD ----
app.post('/api/reset-password', verifyLimiter, async (req, res) => {
    const email = sanitizeInput(req.body.email, 100).toLowerCase();
    const code = sanitizeInput(req.body.code, 6);
    const newPassword = req.body.newPassword || '';

    const stored = resetCodes.get(email);
    if (!stored) {
        return res.status(400).json({ error: 'No reset request found. Please request a new code.' });
    }

    if (stored.attempts >= 5) {
        resetCodes.delete(email);
        return res.status(400).json({ error: 'Too many failed attempts. Please request a new code.' });
    }

    if (Date.now() > stored.expiresAt) {
        resetCodes.delete(email);
        return res.status(400).json({ error: 'Reset code expired. Please request a new one.' });
    }

    if (stored.code !== code) {
        stored.attempts++;
        return res.status(400).json({ error: `Incorrect code. ${5 - stored.attempts} attempts remaining.` });
    }

    if (!isStrongPassword(newPassword)) {
        return res.status(400).json({ error: 'Password must be at least 6 characters with 1 uppercase, 1 lowercase, and 1 number.' });
    }

    const user = users.get(email);
    if (!user) return res.status(400).json({ error: 'User not found.' });

    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(newPassword, salt);
    resetCodes.delete(email);

    res.json({ success: true, message: 'Password reset successfully! You can now sign in.' });
});

// ---- GET PROFILE ----
app.get('/api/profile/:email', (req, res) => {
    const user = users.get(req.params.email?.toLowerCase());
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json(getPublicUser(user));
});

// ---- GOOGLE CLIENT ID (for frontend) ----
app.get('/api/config', (req, res) => {
    res.json({
        googleClientId: (googleClient && GOOGLE_CLIENT_ID) ? GOOGLE_CLIENT_ID : null
    });
});

// ============================================
// SOCKET HANDLERS (unchanged game logic)
// ============================================
io.on('connection', (socket) => {
    console.log(`Player connected: ${socket.id}`);

    socket.on('create-game', ({ playerName, email, timeControl }) => {
        let roomCode = generateRoomCode();
        while (games.has(roomCode)) roomCode = generateRoomCode();
        const timeMs = getTimeMs(timeControl);
        const game = {
            chess: new Chess(),
            players: { white: { id: socket.id, name: sanitizeInput(playerName, 20) || 'Player 1', email: email || null }, black: null },
            roomCode, status: 'waiting',
            timeControl: timeControl || 'unlimited',
            timers: timeMs ? { white: timeMs, black: timeMs } : null,
            lastTickTime: null
        };
        games.set(roomCode, game);
        socket.join(roomCode);
        socket.roomCode = roomCode;
        socket.color = 'white';
        socket.emit('game-created', { roomCode, color: 'white', playerName: game.players.white.name, timeControl: game.timeControl });
    });

    socket.on('join-game', ({ roomCode, playerName, email }) => {
        const code = roomCode.toUpperCase().trim();
        const game = games.get(code);
        if (!game) return socket.emit('join-error', 'Room not found.');
        if (game.status !== 'waiting') return socket.emit('join-error', 'Game already in progress.');
        if (game.players.black) return socket.emit('join-error', 'Room is full.');

        game.players.black = { id: socket.id, name: sanitizeInput(playerName, 20) || 'Player 2', email: email || null };
        game.status = 'playing';
        socket.join(code);
        socket.roomCode = code;
        socket.color = 'black';

        const payload = { roomCode: code, fen: game.chess.fen(), white: game.players.white.name, black: game.players.black.name, timeControl: game.timeControl, timers: game.timers };
        socket.emit('game-joined', { ...payload, color: 'black' });
        io.to(game.players.white.id).emit('opponent-joined', { ...payload, color: 'white' });
        if (game.timers) startTimer(code);
    });

    socket.on('make-move', ({ from, to, promotion }) => {
        const game = games.get(socket.roomCode);
        if (!game || game.status !== 'playing') return;
        const turn = game.chess.turn() === 'w' ? 'white' : 'black';
        if (socket.color !== turn) return socket.emit('move-error', "Not your turn.");
        try {
            const move = game.chess.move({ from, to, promotion: promotion || 'q' });
            if (!move) return socket.emit('move-error', 'Invalid move.');
            if (game.timers) game.lastTickTime = Date.now();
            const state = {
                fen: game.chess.fen(), move, isCheck: game.chess.isCheck(), isCheckmate: game.chess.isCheckmate(),
                isDraw: game.chess.isDraw(), isStalemate: game.chess.isStalemate(), isGameOver: game.chess.isGameOver(),
                turn: game.chess.turn(), history: game.chess.history(), timers: game.timers
            };
            if (state.isGameOver) {
                game.status = 'finished';
                clearTimer(socket.roomCode);
                saveGameToHistory(game, state.isCheckmate ? (game.chess.turn() === 'w' ? 'black' : 'white') : 'draw');
            }
            io.to(socket.roomCode).emit('move-made', state);
        } catch (e) { socket.emit('move-error', 'Invalid move.'); }
    });

    socket.on('resign', () => {
        const game = games.get(socket.roomCode);
        if (!game || game.status !== 'playing') return;
        game.status = 'finished';
        clearTimer(socket.roomCode);
        const winner = socket.color === 'white' ? 'black' : 'white';
        saveGameToHistory(game, winner);
        io.to(socket.roomCode).emit('game-over', { reason: 'resignation', winner, winnerName: game.players[winner].name });
    });

    socket.on('offer-draw', () => {
        const game = games.get(socket.roomCode);
        if (!game || game.status !== 'playing') return;
        const opp = socket.color === 'white' ? game.players.black : game.players.white;
        if (opp) io.to(opp.id).emit('draw-offered', { from: socket.color });
    });

    socket.on('accept-draw', () => {
        const game = games.get(socket.roomCode);
        if (!game || game.status !== 'playing') return;
        game.status = 'finished';
        clearTimer(socket.roomCode);
        saveGameToHistory(game, 'draw');
        io.to(socket.roomCode).emit('game-over', { reason: 'draw-agreement', winner: null });
    });

    socket.on('decline-draw', () => {
        const game = games.get(socket.roomCode);
        if (!game) return;
        const opp = socket.color === 'white' ? game.players.black : game.players.white;
        if (opp) io.to(opp.id).emit('draw-declined');
    });

    socket.on('request-rematch', () => {
        const game = games.get(socket.roomCode);
        if (!game) return;
        if (!game.rematchRequests) game.rematchRequests = new Set();
        game.rematchRequests.add(socket.color);
        const opp = socket.color === 'white' ? game.players.black : game.players.white;
        if (opp) io.to(opp.id).emit('rematch-requested');
        if (game.rematchRequests.size === 2) {
            game.chess = new Chess();
            game.status = 'playing';
            game.rematchRequests = new Set();
            const timeMs = getTimeMs(game.timeControl);
            if (timeMs) game.timers = { white: timeMs, black: timeMs };
            const oldW = game.players.white;
            game.players.white = game.players.black;
            game.players.black = oldW;
            const ws = io.sockets.sockets.get(game.players.white.id);
            const bs = io.sockets.sockets.get(game.players.black.id);
            if (ws) ws.color = 'white';
            if (bs) bs.color = 'black';
            const p = { fen: game.chess.fen(), white: game.players.white.name, black: game.players.black.name, timeControl: game.timeControl, timers: game.timers };
            io.to(game.players.white.id).emit('rematch-start', { ...p, color: 'white' });
            io.to(game.players.black.id).emit('rematch-start', { ...p, color: 'black' });
            if (game.timers) startTimer(game.roomCode);
        }
    });

    socket.on('chat-message', (message) => {
        const game = games.get(socket.roomCode);
        if (!game) return;
        const name = socket.color === 'white' ? game.players.white.name : game.players.black?.name || 'Unknown';
        io.to(socket.roomCode).emit('chat-message', { sender: name, color: socket.color, message: sanitizeInput(message, 200) });
    });

    socket.on('disconnect', () => {
        const game = games.get(socket.roomCode);
        if (!game) return;
        if (game.status === 'playing') {
            const winner = socket.color === 'white' ? 'black' : 'white';
            game.status = 'finished';
            clearTimer(socket.roomCode);
            saveGameToHistory(game, winner);
            io.to(socket.roomCode).emit('game-over', { reason: 'disconnection', winner, winnerName: game.players[winner]?.name || 'Opponent' });
        }
        if (game.status === 'waiting') games.delete(socket.roomCode);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`♔ Chess server running at http://localhost:${PORT}`);
});
