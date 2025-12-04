const api = window.electronAPI;

// --- 窗口控制 ---
document.getElementById('win-min').onclick = () => api.mainMin();
document.getElementById('win-max').onclick = () => api.mainMax();
document.getElementById('win-close').onclick = () => api.mainClose();

// --- 状态数据 ---
let activeSessionId = 'codex'; // 默认选中 Codex
const sessions = [
    { id: 'codex', name: 'Codex (后端)', preview: '系统已连接', time: '12:00' },
    { id: 'secure_group', name: '核心开发组', preview: '密钥交换完毕', time: '11:30' },
    { id: 'pm', name: '产品经理', preview: 'UI 验收中', time: '09:00' }
];

// --- 渲染逻辑 ---
const listEl = document.getElementById('session-list');
const chatTitle = document.getElementById('chat-title');
const msgContainer = document.getElementById('message-container');
const inputArea = document.getElementById('msg-input');

// 初始化渲染
function renderSessions() {
    listEl.innerHTML = '';
    sessions.forEach(s => {
        const div = document.createElement('div');
        div.className = `session-item ${s.id === activeSessionId ? 'active' : ''}`;
        div.onclick = () => switchSession(s.id);
        div.innerHTML = `
            <div class="session-avatar"></div>
            <div class="session-info">
                <div class="session-name">${s.name}</div>
                <div class="session-preview">${s.preview}</div>
            </div>
            <div class="session-time">${s.time}</div>
        `;
        listEl.appendChild(div);
    });
}

function switchSession(id) {
    activeSessionId = id;
    const session = sessions.find(s => s.id === id);
    chatTitle.textContent = session ? session.name : '未选择';
    renderSessions();
    msgContainer.innerHTML = ''; // 切换时清空消息 (实际应加载历史记录)
    addSystemMessage(`已与 ${session.name} 建立 E2EE 加密通道`);
}

// 添加消息 (防 XSS 版)
function addMessage(text, isMe = true, fromId = null) {
    if (!isMe && fromId && fromId !== activeSessionId) {
        // 如果收到的消息不是当前会话的，仅提示 (简单处理)
        console.log(`收到来自 ${fromId} 的消息，但当前不在该窗口`);
        return;
    }

    const row = document.createElement('div');
    row.className = `msg-row ${isMe ? 'me' : 'other'}`;
    
    const avatar = document.createElement('div');
    avatar.className = 'msg-avatar-img';
    
    const bubble = document.createElement('div');
    bubble.className = 'msg-content';
    bubble.textContent = text; // ★ 安全修复: 禁止 innerHTML
    
    row.appendChild(avatar);
    row.appendChild(bubble);
    
    msgContainer.appendChild(row);
    msgContainer.scrollTop = msgContainer.scrollHeight;
}

function addSystemMessage(text) {
    const div = document.createElement('div');
    div.style.textAlign = 'center';
    div.style.fontSize = '12px';
    div.style.color = '#aaa';
    div.style.margin = '10px 0';
    div.textContent = text;
    msgContainer.appendChild(div);
}

// --- 事件监听 ---

// 1. 发送文本消息
document.getElementById('send-btn').onclick = () => {
    const txt = inputArea.value.trim();
    if (!txt) return;

    // UI 立即上屏
    addMessage(txt, true);

    // 调用后端
    api.core.sendMessage(activeSessionId, txt);

    inputArea.value = '';
};

inputArea.onkeydown = (e) => {
    if (e.key === 'Enter' && !e.ctrlKey) {
        e.preventDefault();
        document.getElementById('send-btn').click();
    }
};

// 2. 发送文件 (含安全擦除逻辑)
document.getElementById('btn-send-file').onclick = async () => {
    const filePath = await api.openFileDialog();
    if (filePath) {
        addSystemMessage(`正在加密并发送文件: ${filePath}...`);
        
        // 调用 Bridge 执行: 分片 -> HMAC -> 发送 -> 擦除
        await api.core.sendFile(activeSessionId, filePath);
        
        addSystemMessage(`文件发送完毕，本地源文件已执行 DoD 标准擦除。`);
    }
};

// 3. 注册接收回调
api.core.onMessage((fromId, content, time) => {
    // Bridge 层已完成 DecodeEncString，这里收到的是明文
    addMessage(content, false, fromId);
});

// 启动初始化
renderSessions();
switchSession('codex');
