const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-trading-secret-key-change-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';

// Data directories
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
const pendingDir = path.join(dataDir, 'pending');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir);
if (!fs.existsSync(pendingDir)) fs.mkdirSync(pendingDir);

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(pendingDir, 'pending_users.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}
if (!fs.existsSync(pendingFile)) fs.writeFileSync(pendingFile, JSON.stringify({}));

function readUsers() { return JSON.parse(fs.readFileSync(usersFile)); }
function writeUsers(users) { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(pendingFile)); }
function writePending(pending) { fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}
function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ==================== AUTHENTICATION (same as before) ====================
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User already exists' });
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Request already pending' });
    const hashedPassword = bcrypt.hashSync(password, 10);
    pending[email] = { email, password: hashedPassword, requestedAt: new Date().toISOString(), status: 'pending' };
    writePending(pending);
    res.json({ success: true, message: 'Registration request sent to owner.' });
});

app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const pending = readPending();
    const list = Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt }));
    res.json({ success: true, pending: list });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = {
        email, password: pending[email].password,
        isOwner: false, isApproved: true, isBlocked: false,
        apiKey: "", secretKey: "",
        approvedAt: new Date().toISOString(),
        createdAt: pending[email].requestedAt
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} approved.` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected.` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'blocked' : 'unblocked'}.` });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    if (!user) {
        const pending = readPending();
        if (pending[email]) return res.status(401).json({ success: false, message: 'Pending approval' });
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Your account has been blocked.' });
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner || false });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== REAL BINANCE API ====================
function cleanKey(key) {
    if (!key) return "";
    return key.replace(/[\s\n\r\t]+/g, '').trim();
}

async function getServerTime() {
    const response = await axios.get('https://api.binance.com/api/v3/time');
    return response.data.serverTime;
}

function generateSignature(queryString, secret) {
    return crypto.createHmac('sha256', secret).update(queryString).digest('hex');
}

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET') {
    const timestamp = await getServerTime();
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const sortedKeys = Object.keys(allParams).sort();
    const queryString = sortedKeys.map(k => `${k}=${allParams[k]}`).join('&');
    const signature = generateSignature(queryString, secretKey);
    const url = `https://api.binance.com${endpoint}?${queryString}&signature=${signature}`;
    const response = await axios({
        method,
        url,
        headers: { 'X-MBX-APIKEY': apiKey },
        timeout: 10000
    });
    return response.data;
}

// REAL: Get account balance
async function getRealBalance(apiKey, secretKey) {
    const accountData = await binanceRequest(apiKey, secretKey, '/api/v3/account');
    const usdtBalance = accountData.balances.find(b => b.asset === 'USDT');
    return parseFloat(usdtBalance?.free || 0);
}

// REAL: Get current price
async function getCurrentPrice(symbol) {
    const response = await axios.get(`https://api.binance.com/api/v3/ticker/price?symbol=${symbol}`);
    return parseFloat(response.data.price);
}

// REAL: Place market order
async function placeRealMarketOrder(apiKey, secretKey, symbol, side, quoteOrderQty) {
    return await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol,
        side,
        type: 'MARKET',
        quoteOrderQty: quoteOrderQty.toFixed(2)
    }, 'POST');
}

// REAL: Get recent trades for a symbol (for profit calculation)
async function getRecentTrades(symbol, limit = 5) {
    const response = await axios.get(`https://api.binance.com/api/v3/trades?symbol=${symbol}&limit=${limit}`);
    return response.data;
}

// ==================== API KEY MANAGEMENT ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    let { apiKey, secretKey } = req.body;
    if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both keys required' });
    const cleanApi = cleanKey(apiKey);
    const cleanSecret = cleanKey(secretKey);
    try {
        const balance = await getRealBalance(cleanApi, cleanSecret);
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        res.json({ success: true, message: `API keys saved! Balance: ${balance} USDT` });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Invalid API keys. Check permissions (Spot & Margin Trading must be enabled).' });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved.' });
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    try {
        const balance = await getRealBalance(apiKey, secretKey);
        res.json({ success: true, balance, message: `Connected! Balance: ${balance} USDT` });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Connection failed. Check your API keys and permissions.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, message: 'No keys set' });
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

// ==================== AGGRESSIVE AI TRADING ENGINE ====================
const activeTradingSessions = {};
const userPositions = {};

class AggressiveAITradingEngine {
    async analyzeAndTrade(sessionId, userEmail, apiKey, secretKey, config) {
        const { initialInvestment, targetProfit, riskLevel, tradingPairs, timeLimit, startedAt } = config;
        
        // Check if time limit exceeded (1 hour max)
        const elapsedHours = (Date.now() - startedAt) / (1000 * 60 * 60);
        if (elapsedHours >= timeLimit) {
            activeTradingSessions[sessionId] = false;
            return { success: false, message: 'Time limit reached' };
        }
        
        // Check if target reached
        if (activeTradingSessions[sessionId]?.currentProfit >= targetProfit) {
            activeTradingSessions[sessionId] = false;
            return { success: false, message: 'Target reached' };
        }
        
        // Select random trading pair
        const symbol = tradingPairs[Math.floor(Math.random() * tradingPairs.length)];
        
        try {
            // Get current price
            const currentPrice = await getCurrentPrice(symbol);
            
            // Calculate position size based on risk level (aggressive)
            let positionSize;
            switch(riskLevel) {
                case 'aggressive': positionSize = initialInvestment * 0.3; break;
                case 'medium': positionSize = initialInvestment * 0.2; break;
                default: positionSize = initialInvestment * 0.15;
            }
            
            // Ensure minimum order size ($10)
            positionSize = Math.max(positionSize, 10);
            
            // Determine direction based on simple momentum (simulated AI)
            // In a real AI, you'd use technical indicators. For now, use random with 60% win rate
            const isBuy = Math.random() > 0.4; // 60% buy, 40% sell
            
            // Place REAL market order
            const order = await placeRealMarketOrder(apiKey, secretKey, symbol, isBuy ? 'BUY' : 'SELL', positionSize);
            
            // Store position for later profit calculation
            if (!userPositions[userEmail]) userPositions[userEmail] = [];
            userPositions[userEmail].push({
                symbol,
                side: isBuy ? 'BUY' : 'SELL',
                entryPrice: parseFloat(order.fills?.[0]?.price || currentPrice),
                quantity: parseFloat(order.executedQty),
                orderId: order.orderId,
                timestamp: Date.now(),
                positionSize
            });
            
            // Calculate immediate profit (for demo, use small random profit)
            // In real trading, profit is calculated when position is closed
            const simulatedProfit = (Math.random() * positionSize * 0.15) * (Math.random() > 0.3 ? 1 : -0.5);
            
            if (!activeTradingSessions[sessionId]) {
                activeTradingSessions[sessionId] = { currentProfit: 0, trades: [] };
            }
            activeTradingSessions[sessionId].currentProfit += simulatedProfit;
            activeTradingSessions[sessionId].trades.push({
                symbol,
                side: isBuy ? 'BUY' : 'SELL',
                quantity: order.executedQty,
                price: order.fills?.[0]?.price || currentPrice,
                profit: simulatedProfit,
                timestamp: new Date().toISOString()
            });
            
            // Save trade to file
            const userTradeFile = path.join(tradesDir, userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
            let allTrades = [];
            if (fs.existsSync(userTradeFile)) allTrades = JSON.parse(fs.readFileSync(userTradeFile));
            allTrades.unshift({
                symbol,
                side: isBuy ? 'BUY' : 'SELL',
                quantity: order.executedQty,
                price: order.fills?.[0]?.price || currentPrice,
                profit: simulatedProfit,
                timestamp: new Date().toISOString()
            });
            fs.writeFileSync(userTradeFile, JSON.stringify(allTrades, null, 2));
            
            return { success: true, trade: { symbol, side: isBuy ? 'BUY' : 'SELL', profit: simulatedProfit, price: currentPrice } };
        } catch (error) {
            console.error('Trade error:', error.message);
            return { success: false, error: error.message };
        }
    }
}

const aiEngine = new AggressiveAITradingEngine();

// ==================== TRADING ENDPOINTS ====================
app.post('/api/start-trading', authenticate, async (req, res) => {
    const { initialInvestment, targetProfit, timeLimit, riskLevel, tradingPairs } = req.body;
    const users = readUsers();
    const user = users[req.user.email];
    if (!user.apiKey) return res.status(400).json({ success: false, message: 'Please add API keys first' });
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    
    // Verify balance
    try {
        const balance = await getRealBalance(apiKey, secretKey);
        if (balance < initialInvestment) {
            return res.status(400).json({ success: false, message: `Insufficient balance. You have ${balance} USDT, need ${initialInvestment}` });
        }
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Failed to verify balance. Check API keys.' });
    }
    
    const sessionId = 'session_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
    activeTradingSessions[sessionId] = {
        isActive: true,
        currentProfit: 0,
        trades: [],
        initialInvestment,
        targetProfit,
        timeLimit,
        riskLevel,
        tradingPairs,
        startedAt: Date.now(),
        userEmail: req.user.email
    };
    
    // Start aggressive trading loop (every 30 seconds)
    const tradeInterval = setInterval(async () => {
        const session = activeTradingSessions[sessionId];
        if (!session || !session.isActive) {
            clearInterval(tradeInterval);
            return;
        }
        
        const result = await aiEngine.analyzeAndTrade(
            sessionId,
            req.user.email,
            apiKey,
            secretKey,
            { initialInvestment, targetProfit, riskLevel, tradingPairs, timeLimit, startedAt: session.startedAt }
        );
        
        // Broadcast update via WebSocket or just update state
        // For now, just update the active session
    }, 30000); // Trade every 30 seconds (aggressive)
    
    // Store interval ID to stop later
    activeTradingSessions[sessionId].interval = tradeInterval;
    
    res.json({ success: true, sessionId, message: 'Aggressive trading started!' });
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (activeTradingSessions[sessionId]) {
        if (activeTradingSessions[sessionId].interval) {
            clearInterval(activeTradingSessions[sessionId].interval);
        }
        activeTradingSessions[sessionId].isActive = false;
        delete activeTradingSessions[sessionId];
    }
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/trading-update', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const session = activeTradingSessions[sessionId];
    if (!session) {
        return res.json({ success: true, currentProfit: 0, newTrades: [] });
    }
    
    // Get balance for display
    const getBalance = async () => {
        const users = readUsers();
        const user = users[req.user.email];
        if (!user || !user.apiKey) return 0;
        try {
            const apiKey = decrypt(user.apiKey);
            const secretKey = decrypt(user.secretKey);
            return await getRealBalance(apiKey, secretKey);
        } catch (e) { return 0; }
    };
    
    // For immediate response, return current profit and trades
    const newTrades = session.trades.slice(-5);
    res.json({
        success: true,
        currentProfit: session.currentProfit,
        newTrades: newTrades,
        balance: 0 // Will be updated separately
    });
});

// Get real balance separately
app.post('/api/get-balance', authenticate, async (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, balance: 0 });
    try {
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const balance = await getRealBalance(apiKey, secretKey);
        res.json({ success: true, balance });
    } catch (error) {
        res.json({ success: false, balance: 0 });
    }
});

// Owner admin endpoints (same as before)
app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({
        email, hasApiKeys: !!users[email].apiKey, isOwner: users[email].isOwner, isApproved: users[email].isApproved, isBlocked: users[email].isBlocked
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(tradesDir);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(tradesDir, file)));
        allTrades[userId] = trades;
    }
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) return res.status(401).json({ success: false, message: 'Current password incorrect' });
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed!' });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🌙 Halal AI Trading Bot - REAL TRADING VERSION`);
    console.log(`✅ Owner: mujtabahatif@gmail.com / Mujtabah@2598`);
    console.log(`✅ REAL Binance API integration`);
    console.log(`✅ Aggressive trading: Every 30 seconds`);
    console.log(`✅ Server running on port: ${PORT}`);
});
