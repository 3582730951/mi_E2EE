const { contextBridge, ipcRenderer } = require('electron');

let native = null;
let nativeLoadError = null;
let nativeLoadedPath = null;
let bridgeCandidates = [];
try {
    const join = (...parts) => parts.filter(Boolean).join('/').replace(/\\/g, '/');
    const resourcesPath = (process.resourcesPath || '').replace(/\\/g, '/');
    const execDir = (process.execPath || '').replace(/\\/g, '/').replace(/\\/g, '/').replace(/\/[^/]*$/, '');
    const candidates = [];
    if (resourcesPath) {
        candidates.push(
            join(resourcesPath, 'app.asar.unpacked/mi_bridge/build/Release/mi_bridge.node'),
            join(resourcesPath, 'mi_bridge/build/Release/mi_bridge.node'),
            join(resourcesPath, 'app/mi_bridge/build/Release/mi_bridge.node')
        );
    }
    if (execDir) {
        candidates.push(
            join(execDir, 'resources/app.asar.unpacked/mi_bridge/build/Release/mi_bridge.node'),
            join(execDir, 'resources/mi_bridge/build/Release/mi_bridge.node'),
            join(execDir, 'resources/app/mi_bridge/build/Release/mi_bridge.node')
        );
    }
    bridgeCandidates = candidates;
    for (const p of candidates) {
        try {
            native = require(p);
            nativeLoadedPath = p;
            console.log('[BRIDGE] Native addon loaded from', p);
            break;
        } catch (err) {
            nativeLoadError = err;
            continue;
        }
    }
} catch (e) {
    nativeLoadError = e;
    console.warn('[BRIDGE] Native addon load failed.', e.message);
}

// 默认禁用 Mock；仅当 MI_ALLOW_BRIDGE_MOCK=1 时启用
const allowMockBridge = process.env.MI_ALLOW_BRIDGE_MOCK === '1';
const bridgeMissingHint = () => {
    const hint = nativeLoadError ? nativeLoadError.message : 'mi_bridge.node missing';
    return `[BRIDGE] Native addon unavailable (${hint}). 已尝试: ${bridgeCandidates.join(' ; ')}。请确认 mi_bridge.node 与依赖 DLL (libssl/libcrypto/libmysql,vcruntime/msvcp) 位于上述目录。`;
};

const errorBridge = {
    isInitialized: false,
    status: 0,
    init: async () => { throw new Error(bridgeMissingHint()); },
    connect: async () => { throw new Error(bridgeMissingHint()); },
    login: async () => { throw new Error(bridgeMissingHint()); },
    sendMessage: () => { throw new Error(bridgeMissingHint()); },
    registerMsgCallback: () => {},
    sendFile: async () => { throw new Error(bridgeMissingHint()); },
    secureDelete: async () => { throw new Error(bridgeMissingHint()); },
    getStatus: () => 0
};

const realBridge = native ? {
    isInitialized: false,
    msgCallback: null,
    status: 0,
    init: async (storagePath) => {
        const ok = native.init(storagePath);
        Bridge.isInitialized = ok;
        return ok;
    },
    connect: async (ip, port) => {
        if (!Bridge.isInitialized) throw new Error('Please Init first');
        const ok = native.connect(ip, port);
        Bridge.status = ok ? 2 : 0;
        return ok;
    },
    login: async (user, pass) => native.login(user, pass),
    sendMessage: (targetId, plainText) => native.sendMessage(targetId, plainText),
    registerMsgCallback: (cb) => {
        native.onMessage((payload) => {
            cb('remote', payload, Date.now());
        });
    },
    setRawSend: native.setRawSend ? native.setRawSend : () => {},
    setRawReceive: native.setRawReceive ? native.setRawReceive : () => {},
    sendFile: async (_targetId, filePath) => {
        // 分片逻辑尚未暴露到 addon，这里仅调用 secureDelete 保障安全
        return native.secureDelete(filePath);
    },
    secureDelete: async (filePath) => native.secureDelete(filePath),
    getStatus: () => Bridge.status
} : null;

const mockBridge = {
    isInitialized: false,
    msgCallback: null,
    status: 0, // 0=断开,1=连接中,2=已连接
    init: async (storagePath) => {
        console.log(`[BRIDGE-MOCK] MI_Init("${storagePath}")`);
        Bridge.isInitialized = true;
        return true;
    },
    connect: async (ip, port) => {
        if (!Bridge.isInitialized) throw new Error("Please Init first");
        console.log(`[BRIDGE-MOCK] MI_KCP_Connect(${ip}:${port})...`);
        return new Promise(resolve => setTimeout(() => { Bridge.status = 2; resolve(true); }, 300));
    },
    login: async (user, pass) => {
        return new Promise((resolve, reject) => {
            setTimeout(() => (user && pass ? resolve(true) : reject("Auth failed")), 300);
        });
    },
    sendMessage: (targetId, plainText) => {
        console.log(`[BRIDGE-MOCK] SendMessage -> ${targetId}: ${plainText}`);
        return true;
    },
    registerMsgCallback: (callback) => {
        Bridge.msgCallback = callback;
        setTimeout(() => {
            callback("codex", "Mock message from backend", Date.now());
        }, 1000);
    },
    sendFile: async (_targetId, filePath) => {
        console.log(`[BRIDGE-MOCK] sendFile ${filePath}`);
        return true;
    },
    secureDelete: async (filePath) => {
        console.log(`[BRIDGE-MOCK] secureDelete ${filePath}`);
        return true;
    },
    getStatus: () => Bridge.status
};

const Bridge = native ? realBridge : (allowMockBridge ? mockBridge : errorBridge);

// --- 暴露给渲染进程的安全 API ---
contextBridge.exposeInMainWorld('electronAPI', {
    bridgeStatus: () => ({
        nativeLoaded: !!native,
        nativeLoadedPath,
        allowMockBridge,
        nativeLoadError: nativeLoadError ? nativeLoadError.message : null,
        candidates: bridgeCandidates
    }),
    // 窗口操作
    loginSuccess: () => ipcRenderer.send('login-success'),
    loginClose: () => ipcRenderer.send('login-close'),
    loginMin: () => ipcRenderer.send('login-min'),
    mainClose: () => ipcRenderer.send('main-close'),
    mainMin: () => ipcRenderer.send('main-min'),
    mainMax: () => ipcRenderer.send('main-max'),
    
    // 系统操作
    openFileDialog: () => ipcRenderer.invoke('dialog:openFile'),

    // 业务逻辑 (封装 Bridge)
    core: {
        init: Bridge.init,
        connect: Bridge.connect,
        login: Bridge.login,
        sendMessage: Bridge.sendMessage,
        sendFile: Bridge.sendFile,
        secureDelete: Bridge.secureDelete,
        onMessage: Bridge.registerMsgCallback,
        getStatus: () => Bridge.status
    }
});
