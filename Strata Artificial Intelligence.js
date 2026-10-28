"use strict";

const DB_NAME = "slateDB";
const DB_VERSION = 1;
let dbInstance = null;

function openDB() {
  return new Promise((resolve, reject) => {
    if (dbInstance) return resolve(dbInstance);
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains("users")) {
        const users = db.createObjectStore("users", { keyPath: "id", autoIncrement: true });
        users.createIndex("username", "username", { unique: true });
      }
      if (!db.objectStoreNames.contains("chats")) {
        const chats = db.createObjectStore("chats", { keyPath: "id", autoIncrement: true });
        chats.createIndex("userId", "userId", { unique: false });
      }
      if (!db.objectStoreNames.contains("settings")) {
        db.createObjectStore("settings", { keyPath: "userId" });
      }
    };

    req.onsuccess = (e) => { dbInstance = e.target.result; resolve(dbInstance); };
    req.onerror = (e) => reject(e.target.error);
  });
}

function store(name, mode) {
  return dbInstance.transaction(name, mode).objectStore(name);
}

async function dbAdd(storeName, value) {
  await openDB();
  return new Promise((resolve, reject) => {
    const req = store(storeName, "readwrite").add(value);
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror = (e) => reject(e.target.error);
  });
}

async function dbPut(storeName, value) {
  await openDB();
  return new Promise((resolve, reject) => {
    const req = store(storeName, "readwrite").put(value);
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror = (e) => reject(e.target.error);
  });
}

async function dbGet(storeName, key) {
  await openDB();
  return new Promise((resolve, reject) => {
    const req = store(storeName, "readonly").get(key);
    req.onsuccess = (e) => resolve(e.target.result || null);
    req.onerror = (e) => reject(e.target.error);
  });
}

async function dbDelete(storeName, key) {
  await openDB();
  return new Promise((resolve, reject) => {
    const req = store(storeName, "readwrite").delete(key);
    req.onsuccess = () => resolve(true);
    req.onerror = (e) => reject(e.target.error);
  });
}

async function dbGetByIndex(storeName, indexName, value) {
  await openDB();
  return new Promise((resolve, reject) => {
    const req = store(storeName, "readonly").index(indexName).get(value);
    req.onsuccess = (e) => resolve(e.target.result || null);
    req.onerror = (e) => reject(e.target.error);
  });
}

async function dbGetAllByIndex(storeName, indexName, value) {
  await openDB();
  return new Promise((resolve, reject) => {
    const req = store(storeName, "readonly").index(indexName).getAll(value);
    req.onsuccess = (e) => resolve(e.target.result || []);
    req.onerror = (e) => reject(e.target.error);
  });
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBuf(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr.buffer;
}

function randomSaltHex(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return bufToHex(arr.buffer);
}

async function pbkdf2Hash(text, saltHex, iterations = 120000) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(text), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: hexToBuf(saltHex), iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bufToHex(bits);
}

function generateRecoveryCode() {
  const arr = new Uint32Array(12);
  crypto.getRandomValues(arr);
  const digits = Array.from(arr).map((n) => n % 10).join("");
  return digits.match(/.{1,4}/g).join("-");
}

function normalizeCode(code) {
  return code.replace(/[^0-9]/g, "");
}

const SESSION_KEY = "slate_uid";

function getSessionUserId() {
  const v = localStorage.getItem(SESSION_KEY);
  return v ? parseInt(v, 10) : null;
}

function setSessionUserId(id) {
  localStorage.setItem(SESSION_KEY, String(id));
}

function clearSession() {
  localStorage.removeItem(SESSION_KEY);
}

async function signUpUser(username, password) {
  const existing = await dbGetByIndex("users", "username", username);
  if (existing) throw new Error("That username is already taken.");

  const passwordSalt = randomSaltHex();
  const passwordHash = await pbkdf2Hash(password, passwordSalt);
  const recoveryCode = generateRecoveryCode();
  const recoverySalt = randomSaltHex();
  const recoveryHash = await pbkdf2Hash(normalizeCode(recoveryCode), recoverySalt);

  const user = { username, passwordHash, passwordSalt, recoveryHash, recoverySalt, createdAt: Date.now() };
  const id = await dbAdd("users", user);
  return { id, recoveryCode };
}

async function loginUser(username, password) {
  const user = await dbGetByIndex("users", "username", username);
  if (!user) throw new Error("Invalid username or password.");
  const hash = await pbkdf2Hash(password, user.passwordSalt);
  if (hash !== user.passwordHash) throw new Error("Invalid username or password.");
  return user;
}

async function resetPasswordWithCode(username, code, newPassword) {
  const user = await dbGetByIndex("users", "username", username);
  if (!user) throw new Error("No account found for that username.");

  const hash = await pbkdf2Hash(normalizeCode(code), user.recoverySalt);
  if (hash !== user.recoveryHash) throw new Error("That recovery passkey doesn't match.");

  const passwordSalt = randomSaltHex();
  const passwordHash = await pbkdf2Hash(newPassword, passwordSalt);
  const newRecoveryCode = generateRecoveryCode();
  const recoverySalt = randomSaltHex();
  const recoveryHash = await pbkdf2Hash(normalizeCode(newRecoveryCode), recoverySalt);

  user.passwordHash = passwordHash;
  user.passwordSalt = passwordSalt;
  user.recoveryHash = recoveryHash;
  user.recoverySalt = recoverySalt;
  await dbPut("users", user);
  return newRecoveryCode;
}

const PROVIDERS = {
  groq: {
    label: "Groq Cloud",
    endpoint: "https://api.groq.com/openai/v1/chat/completions",
    defaultModel: "openai/gpt-oss-120b"
  },
};

const MAX_MESSAGE_CHARS = 8000;
const MAX_REPLY_TOKENS = 500;
const CONTEXT_MESSAGES = 6;
const CHARS_PER_TOKEN = 4;
const MESSAGE_OVERHEAD_TOKENS = 4;

const fmt = (n) => Number(n).toLocaleString();

const DEFAULT_PERSONAS = [
  { name: "Coder", prompt: "You are Strata, an expert software engineer. Give correct, minimal code with a one or two line explanation. Prefer modern idioms and mention edge cases only when they matter." },
  { name: "Editor", prompt: "You are Strata, a sharp copy editor. Improve clarity, grammar and flow while keeping the author's voice. Return the edited text first, then a short list of the main changes." },
  { name: "Explainer", prompt: "You are Strata, a patient teacher. Explain concepts in plain language with one concrete example or analogy. Keep answers short and build from simple to detailed." },
  { name: "Critic", prompt: "You are Strata, a constructive critic. Point out flaws, risks and weak assumptions directly, then suggest a concrete improvement for each." }
];

const DEFAULT_TEMPLATES = [
  { name: "Summarize", text: "Summarize the following in 5 bullet points:\n\n{{text}}" },
  { name: "Explain code", text: "Explain what this code does, step by step:\n\n{{code}}" },
  { name: "Find the bug", text: "Find the bug in this code and show the fix:\n\n{{code}}\n\nExpected behavior: {{expected}}" },
  { name: "Translate", text: "Translate the following into {{language}}:\n\n{{text}}" },
  { name: "Rewrite", text: "Rewrite this to be {{tone}}:\n\n{{text}}" }
];

function ensureSettingsDefaults(settings) {
  let changed = false;
  if (!Array.isArray(settings.personas)) {
    settings.personas = DEFAULT_PERSONAS.map((p) => ({ id: crypto.randomUUID(), ...p }));
    changed = true;
  }
  if (!Array.isArray(settings.templates)) {
    settings.templates = DEFAULT_TEMPLATES.map((t) => ({ id: crypto.randomUUID(), ...t }));
    changed = true;
  }
  if (!Array.isArray(settings.folders)) {
    settings.folders = [];
    changed = true;
  }
  return changed;
}

async function describeErrorResponse(res, fallbackPrefix) {
  let msg = `${fallbackPrefix} (status ${res.status}).`;
  try {
    const j = await res.json();
    if (j.error && j.error.message) msg = j.error.message;
  } catch (e) {
  }
  return msg;
}

async function streamChatCompletion({ provider, apiKey, model, messages, temperature, signal, onDelta }) {
  const endpoint = PROVIDERS[provider].endpoint;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + apiKey },
    body: JSON.stringify({ 
      model, 
      messages, 
      temperature, 
      max_tokens: MAX_REPLY_TOKENS,
      stream: true 
    }),
    signal
  });
  if (!response.ok) throw new Error(await describeErrorResponse(response, "Request failed"));

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let fullText = "";
  let usage = null;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop();

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line.startsWith("data:")) continue;
      const data = line.slice(5).trim();
      if (data === "[DONE]") continue;
      try {
        const json = JSON.parse(data);
        const reported = json.usage || (json.x_groq && json.x_groq.usage);
        if (reported) usage = reported;
        const delta = json.choices && json.choices[0] && json.choices[0].delta ? json.choices[0].delta.content : "";
        if (delta) {
          fullText += delta;
          if (onDelta) onDelta(delta, fullText);
        }
      } catch (e) {
      }
    }
  }

  return { text: fullText, usage };
}

async function loadUserSettings(userId) {
  let settings = await dbGet("settings", userId);
  if (!settings) {
    settings = {
      userId,
      provider: "groq",
      apiKeyGroq: "",
      temperature: 0.7,
      systemPrompt: "You are Strata, a highly concise assistant. You must provide extremely brief and direct answers. Limit your output to essential information to minimize token usage.",
      theme: "dark"
    };
    await dbPut("settings", settings);
  } else if (typeof settings.systemPrompt === "string" && settings.systemPrompt.startsWith("You are Slate,")) {
    settings.systemPrompt = settings.systemPrompt.replace("You are Slate,", "You are Strata,");
    await dbPut("settings", settings);
  }
  if (ensureSettingsDefaults(settings)) await dbPut("settings", settings);
  return settings;
}

function apiKeyFor(settings, provider) {
  return settings.apiKeyGroq;
}

let state = {
  user: null,
  settings: null,
  chats: [],
  activeChatId: null,
  streaming: false,
  abortController: null,
  stagedFiles: []
};

function resetState() {
  state.user = null;
  state.settings = null;
  state.chats = [];
  state.activeChatId = null;
  state.streaming = false;
  state.abortController = null;
  state.stagedFiles = [];
}

const el = (id) => document.getElementById(id);

function showAuthScreen() {
  el("authScreen").classList.remove("hidden");
  el("appScreen").classList.add("hidden");
}

function showAppScreen() {
  el("authScreen").classList.add("hidden");
  el("appScreen").classList.remove("hidden");
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  el("themeDark").classList.toggle("active", theme === "dark");
  el("themeLight").classList.toggle("active", theme === "light");
}

function autoResize(textarea) {
  textarea.style.height = "auto";
  textarea.style.height = Math.min(textarea.scrollHeight, 200) + "px";
}

function closeSidebarOnMobile() {
  if (window.innerWidth <= 760) el("sidebar").classList.remove("open");
}

function sortedChats() {
  return [...state.chats].sort((a, b) => b.updatedAt - a.updatedAt);
}

function folderById(id) {
  return state.settings.folders.find((f) => f.id === id) || null;
}

function findMatch(chat, query) {
  for (const msg of chat.messages) {
    const content = msg.content || "";
    const index = content.toLowerCase().indexOf(query);
    if (index === -1) continue;
    const start = Math.max(0, index - 24);
    const end = Math.min(content.length, index + query.length + 48);
    return {
      msgId: msg.id,
      before: (start > 0 ? "…" : "") + content.slice(start, index).replace(/\s+/g, " "),
      hit: content.slice(index, index + query.length).replace(/\s+/g, " "),
      after: content.slice(index + query.length, end).replace(/\s+/g, " ") + (end < content.length ? "…" : "")
    };
  }
  return chat.title.toLowerCase().includes(query) ? { msgId: null } : null;
}

function buildListLabel(text) {
  const div = document.createElement("div");
  div.className = "list-label";
  div.textContent = text;
  return div;
}

function buildListNote(text) {
  const div = document.createElement("div");
  div.className = "list-note";
  div.textContent = text;
  return div;
}

async function setChatFolder(chat, folderId) {
  chat.folderId = folderId;
  await dbPut("chats", chat);
  renderChatList(el("searchChats").value);
}

async function promptCreateFolder() {
  const name = prompt("Folder name");
  if (!name || !name.trim()) return null;
  const folder = { id: crypto.randomUUID(), name: name.trim().slice(0, 40), collapsed: false };
  state.settings.folders.push(folder);
  await dbPut("settings", state.settings);
  renderChatList(el("searchChats").value);
  return folder;
}

function moveMenuItems(chat) {
  const items = state.settings.folders.map((folder) => ({
    label: folder.name,
    icon: "ph-folder",
    active: chat.folderId === folder.id,
    onClick: () => setChatFolder(chat, folder.id)
  }));
  if (items.length) items.push({ divider: true });
  items.push({ label: "No folder", icon: "ph-tray", active: !folderById(chat.folderId), onClick: () => setChatFolder(chat, null) });
  items.push({
    label: "New folder…",
    icon: "ph-folder-plus",
    onClick: async () => {
      const folder = await promptCreateFolder();
      if (folder) await setChatFolder(chat, folder.id);
    }
  });
  return items;
}

function buildChatItem(chat, match = null) {
  const item = document.createElement("div");
  item.className = "chat-item" + (chat.id === state.activeChatId ? " active" : "");
  item.innerHTML = `
    <span class="chat-item-main">
      <span class="chat-item-title"></span>
    </span>
    <span class="chat-item-actions">
      <button data-act="pin" title="${chat.pinned ? "Unpin" : "Pin"}"><i class="ph ${chat.pinned ? "ph-push-pin-slash" : "ph-push-pin"}"></i></button>
      <button data-act="move" title="Move to folder"><i class="ph ph-folder"></i></button>
      <button data-act="rename" title="Rename"><i class="ph ph-pencil-simple"></i></button>
      <button data-act="delete" title="Delete"><i class="ph ph-trash"></i></button>
    </span>
  `;
  item.querySelector(".chat-item-title").textContent = chat.title;

  if (match && match.hit) {
    const snippet = document.createElement("span");
    snippet.className = "chat-item-snippet";
    const mark = document.createElement("mark");
    mark.textContent = match.hit;
    snippet.append(match.before, mark, match.after);
    item.querySelector(".chat-item-main").appendChild(snippet);
  }

  item.addEventListener("click", (e) => {
    if (e.target.closest(".chat-item-actions")) return;
    selectChat(chat.id, match && match.msgId ? { msgId: match.msgId } : null);
  });

  item.querySelector('[data-act="pin"]').addEventListener("click", async (e) => {
    e.stopPropagation();
    chat.pinned = !chat.pinned;
    await dbPut("chats", chat);
    renderChatList(el("searchChats").value);
  });

  item.querySelector('[data-act="move"]').addEventListener("click", (e) => {
    e.stopPropagation();
    openPopup(e.currentTarget, moveMenuItems(chat), { placement: "below" });
  });

  item.querySelector('[data-act="rename"]').addEventListener("click", async (e) => {
    e.stopPropagation();
    const name = prompt("Rename chat", chat.title);
    if (name && name.trim()) {
      chat.title = name.trim();
      chat.updatedAt = Date.now();
      await dbPut("chats", chat);
      renderChatList(el("searchChats").value);
      if (chat.id === state.activeChatId) el("chatTitle").textContent = chat.title;
    }
  });

  item.querySelector('[data-act="delete"]').addEventListener("click", async (e) => {
    e.stopPropagation();
    if (!confirm("Delete this chat?")) return;
    await dbDelete("chats", chat.id);
    state.chats = state.chats.filter((c) => c.id !== chat.id);
    if (state.activeChatId === chat.id) {
      if (state.chats.length) selectChat(sortedChats()[0].id);
      else newChat();
    }
    renderChatList(el("searchChats").value);
  });

  return item;
}

function buildFolderHead(folder, count) {
  const head = document.createElement("div");
  head.className = "folder-head";
  head.innerHTML = `
    <i class="ph ${folder.collapsed ? "ph-caret-right" : "ph-caret-down"}"></i>
    <i class="ph ${folder.collapsed ? "ph-folder" : "ph-folder-open"}"></i>
    <span class="folder-name"></span>
    <span class="folder-count">${count}</span>
    <span class="folder-head-actions">
      <button data-act="add" title="New chat in folder"><i class="ph ph-plus"></i></button>
      <button data-act="rename" title="Rename folder"><i class="ph ph-pencil-simple"></i></button>
      <button data-act="delete" title="Delete folder"><i class="ph ph-trash"></i></button>
    </span>
  `;
  head.querySelector(".folder-name").textContent = folder.name;

  head.addEventListener("click", async (e) => {
    if (e.target.closest(".folder-head-actions")) return;
    folder.collapsed = !folder.collapsed;
    await dbPut("settings", state.settings);
    renderChatList(el("searchChats").value);
  });

  head.querySelector('[data-act="add"]').addEventListener("click", (e) => {
    e.stopPropagation();
    newChat(folder.id);
  });

  head.querySelector('[data-act="rename"]').addEventListener("click", async (e) => {
    e.stopPropagation();
    const name = prompt("Rename folder", folder.name);
    if (!name || !name.trim()) return;
    folder.name = name.trim().slice(0, 40);
    await dbPut("settings", state.settings);
    renderChatList(el("searchChats").value);
  });

  head.querySelector('[data-act="delete"]').addEventListener("click", async (e) => {
    e.stopPropagation();
    if (!confirm(`Delete the folder "${folder.name}"? Its chats will be kept.`)) return;
    for (const chat of state.chats.filter((c) => c.folderId === folder.id)) {
      chat.folderId = null;
      await dbPut("chats", chat);
    }
    state.settings.folders = state.settings.folders.filter((f) => f.id !== folder.id);
    await dbPut("settings", state.settings);
    renderChatList(el("searchChats").value);
  });

  return head;
}

function renderChatList(filter = "") {
  const listEl = el("chatList");
  listEl.innerHTML = "";
  const query = filter.trim().toLowerCase();
  const chats = sortedChats();

  if (query) {
    let found = 0;
    chats.forEach((chat) => {
      const match = findMatch(chat, query);
      if (!match) return;
      found++;
      listEl.appendChild(buildChatItem(chat, match));
    });
    if (!found) listEl.appendChild(buildListNote("No matching chats or messages"));
    return;
  }

  const pinned = chats.filter((c) => c.pinned);
  if (pinned.length) {
    listEl.appendChild(buildListLabel("Pinned"));
    pinned.forEach((c) => listEl.appendChild(buildChatItem(c)));
  }

  const folders = state.settings.folders;
  folders.forEach((folder) => {
    const inFolder = chats.filter((c) => !c.pinned && c.folderId === folder.id);
    listEl.appendChild(buildFolderHead(folder, inFolder.length));
    if (folder.collapsed || !inFolder.length) return;
    const wrap = document.createElement("div");
    wrap.className = "folder-children";
    inFolder.forEach((c) => wrap.appendChild(buildChatItem(c)));
    listEl.appendChild(wrap);
  });

  const loose = chats.filter((c) => !c.pinned && !folderById(c.folderId));
  if (loose.length) {
    if (pinned.length || folders.length) listEl.appendChild(buildListLabel("Chats"));
    loose.forEach((c) => listEl.appendChild(buildChatItem(c)));
  }
}

async function newChat(folderId = null) {
  const chat = {
    userId: state.user.id,
    title: "New chat",
    messages: [],
    systemPrompt: state.settings.systemPrompt,
    temperature: state.settings.temperature,
    personaId: null,
    pinned: false,
    folderId,
    createdAt: Date.now(),
    updatedAt: Date.now()
  };
  const folder = folderId ? folderById(folderId) : null;
  if (folder && folder.collapsed) {
    folder.collapsed = false;
    await dbPut("settings", state.settings);
  }
  const id = await dbAdd("chats", chat);
  chat.id = id;
  state.chats.unshift(chat);
  renderChatList(el("searchChats").value);
  selectChat(id);
}

function getActiveChat() {
  return state.chats.find((c) => c.id === state.activeChatId);
}

function flashMessage(msgId) {
  const row = el("messages").querySelector(`[data-id="${msgId}"]`);
  if (!row) return;
  row.classList.add("flash");
  row.scrollIntoView({ block: "center" });
  setTimeout(() => row.classList.remove("flash"), 1900);
}

function selectChat(id, highlight = null) {
  state.activeChatId = id;
  const chat = getActiveChat();
  el("chatTitle").textContent = chat.title;
  state.stagedFiles = [];
  renderStagedFiles();
  renderChatList(el("searchChats").value);
  renderMessages(chat);
  updateChatChrome();
  if (highlight && highlight.msgId) flashMessage(highlight.msgId);
  closeSidebarOnMobile();
}

function renderMessages(chat) {
  const container = el("messages");
  container.innerHTML = "";
  if (!chat.messages.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.id = "emptyState";
    empty.innerHTML = `
      <svg class="logo-mark logo-mark-xl" viewBox="0 0 32 26" xmlns="http://www.w3.org/2000/svg">
        <polygon points="16,1 30,6 16,11 2,6" fill="currentColor"></polygon>
        <polygon points="16,8 30,13 16,18 2,13" fill="currentColor" opacity="0.6"></polygon>
        <polygon points="16,15 30,20 16,25 2,20" fill="currentColor" opacity="0.3"></polygon>
      </svg>
      <h2>How can I help you today?</h2>
      <p>Start a conversation. Set your API key in Settings first.</p>
    `;
    container.appendChild(empty);
    return;
  }
  chat.messages.forEach((msg) => container.appendChild(buildMessageEl(msg)));
  container.scrollTop = container.scrollHeight;
}

function buildMessageEl(msg) {
  const row = document.createElement("div");
  row.className = "msg-row " + msg.role;
  row.dataset.id = msg.id;

  const avatar = document.createElement("div");
  avatar.className = "msg-avatar";
  if (msg.role === "assistant") {
    avatar.innerHTML = `<svg width="18" height="18" viewBox="0 0 32 26" xmlns="http://www.w3.org/2000/svg"><polygon points="16,1 30,6 16,11 2,6" fill="currentColor"></polygon><polygon points="16,8 30,13 16,18 2,13" fill="currentColor" opacity="0.6"></polygon><polygon points="16,15 30,20 16,25 2,20" fill="currentColor" opacity="0.3"></polygon></svg>`;
  }

  const body = document.createElement("div");
  body.className = "msg-body";

  const roleLabel = document.createElement("div");
  roleLabel.className = "msg-role";
  roleLabel.textContent = msg.role === "user" ? "You" : "Strata";

  const content = document.createElement("div");
  content.className = "msg-content";
  renderContentInto(content, msg.content);

  const actions = document.createElement("div");
  actions.className = "msg-actions";

  const copyBtn = document.createElement("button");
  copyBtn.innerHTML = `<i class="ph ph-copy"></i> Copy`;
  copyBtn.addEventListener("click", () => navigator.clipboard.writeText(msg.content));
  actions.appendChild(copyBtn);

  if (msg.role === "user") {
    const editBtn = document.createElement("button");
    editBtn.innerHTML = `<i class="ph ph-pencil-simple"></i> Edit`;
    editBtn.addEventListener("click", () => startEditMessage(row, msg));
    actions.appendChild(editBtn);
  } else {
    const regenBtn = document.createElement("button");
    regenBtn.innerHTML = `<i class="ph ph-arrows-clockwise"></i> Retry`;
    regenBtn.addEventListener("click", () => regenerateFrom(msg.id));
    actions.appendChild(regenBtn);
  }

  if (msg.versions && msg.versions.length > 1) {
    actions.classList.add("has-versions");
    const switcher = document.createElement("span");
    switcher.className = "ver-switch";
    const prev = document.createElement("button");
    prev.innerHTML = `<i class="ph ph-caret-left"></i>`;
    prev.disabled = msg.vIndex === 0;
    prev.addEventListener("click", () => switchVersion(msg.id, -1));
    const label = document.createElement("span");
    label.textContent = `${msg.vIndex + 1} / ${msg.versions.length}`;
    const next = document.createElement("button");
    next.innerHTML = `<i class="ph ph-caret-right"></i>`;
    next.disabled = msg.vIndex === msg.versions.length - 1;
    next.addEventListener("click", () => switchVersion(msg.id, 1));
    switcher.append(prev, label, next);
    actions.appendChild(switcher);
  }

  if (msg.role === "assistant" && msg.usage) {
    const meta = document.createElement("span");
    meta.className = "msg-meta";
    meta.textContent = `${msg.usage.estimated ? "≈ " : ""}${fmt(msg.usage.total)} tokens`;
    meta.title = `Prompt ${fmt(msg.usage.prompt)} · Reply ${fmt(msg.usage.completion)}${msg.usage.estimated ? " (estimated)" : ""}`;
    actions.appendChild(meta);
  }

  body.appendChild(roleLabel);
  body.appendChild(content);
  body.appendChild(actions);
  row.appendChild(avatar);
  row.appendChild(body);
  return row;
}

function renderContentInto(node, text) {
  node.innerHTML = marked.parse(text || "");
  node.querySelectorAll("pre code").forEach((block) => {
    hljs.highlightElement(block);
    const pre = block.parentElement;
    if (!pre.querySelector(".code-copy-btn")) {
      const btn = document.createElement("button");
      btn.className = "code-copy-btn";
      btn.innerHTML = `<i class="ph ph-copy"></i> Copy`;
      btn.addEventListener("click", () => navigator.clipboard.writeText(block.textContent));
      pre.appendChild(btn);
    }
  });
}

function stashActive(msg, tail) {
  if (!msg.versions) {
    msg.versions = [{}];
    msg.vIndex = 0;
  }
  const version = msg.versions[msg.vIndex];
  version.content = msg.content;
  version.usage = msg.usage || null;
  version.tail = tail;
}

function activateVersion(msg, index) {
  msg.vIndex = index;
  const version = msg.versions[index];
  msg.content = version.content;
  msg.usage = version.usage || null;
  return version.tail || [];
}

function addVersion(msg, tail, content) {
  stashActive(msg, tail);
  msg.versions.push({ content, usage: null, tail: [] });
  msg.vIndex = msg.versions.length - 1;
  msg.content = content;
  msg.usage = null;
  msg.timestamp = Date.now();
}

async function switchVersion(msgId, direction) {
  if (state.streaming) return;
  const chat = getActiveChat();
  const idx = chat.messages.findIndex((m) => m.id === msgId);
  if (idx === -1) return;
  const msg = chat.messages[idx];
  const target = msg.vIndex + direction;
  if (target < 0 || target >= msg.versions.length) return;
  stashActive(msg, chat.messages.slice(idx + 1));
  const tail = activateVersion(msg, target);
  chat.messages = chat.messages.slice(0, idx + 1).concat(tail);
  await dbPut("chats", chat);
  renderMessages(chat);
  const row = el("messages").querySelector(`[data-id="${msgId}"]`);
  if (row) row.scrollIntoView({ block: "center" });
  updateTokenUI();
}

function startEditMessage(row, msg) {
  if (state.streaming) return;
  const body = row.querySelector(".msg-body");
  const content = body.querySelector(".msg-content");
  const actions = body.querySelector(".msg-actions");

  const textarea = document.createElement("textarea");
  textarea.className = "msg-edit-area";
  textarea.value = msg.content;

  const saveBtn = document.createElement("button");
  saveBtn.innerHTML = `<i class="ph ph-paper-plane-right"></i> Save & submit`;
  saveBtn.className = "auth-btn secondary";
  saveBtn.addEventListener("click", async () => {
    const newText = textarea.value.trim();
    const chat = getActiveChat();
    if (!newText || newText === msg.content) {
      renderMessages(chat);
      return;
    }
    if (newText.length > MAX_MESSAGE_CHARS) {
      alert("Message is too long. Please reduce the text to comply with strict API usage limits.");
      return;
    }
    const idx = chat.messages.findIndex((m) => m.id === msg.id);
    addVersion(chat.messages[idx], chat.messages.slice(idx + 1), newText);
    chat.messages = chat.messages.slice(0, idx + 1);
    chat.updatedAt = Date.now();
    await dbPut("chats", chat);
    renderMessages(chat);
    runAssistantResponse(chat);
  });

  const cancelBtn = document.createElement("button");
  cancelBtn.textContent = "Cancel";
  cancelBtn.className = "auth-btn secondary";
  cancelBtn.addEventListener("click", () => renderMessages(getActiveChat()));

  const editActions = document.createElement("div");
  editActions.className = "edit-actions";
  editActions.append(saveBtn, cancelBtn);

  content.replaceWith(textarea);
  actions.innerHTML = "";
  actions.classList.remove("has-versions");
  actions.appendChild(editActions);
  textarea.focus();
}

async function regenerateFrom(assistantMsgId) {
  if (state.streaming) return;
  const chat = getActiveChat();
  const idx = chat.messages.findIndex((m) => m.id === assistantMsgId);
  if (idx === -1) return;
  const msg = chat.messages[idx];
  addVersion(msg, chat.messages.slice(idx + 1), "");
  chat.messages = chat.messages.slice(0, idx + 1);
  await dbPut("chats", chat);
  renderMessages(chat);
  runAssistantResponse(chat, msg);
}

function setStreamingUI(isStreaming) {
  state.streaming = isStreaming;
  el("sendBtn").classList.toggle("hidden", isStreaming);
  el("stopBtn").classList.toggle("hidden", !isStreaming);
}

function stopStreaming() {
  if (state.abortController) state.abortController.abort();
}

function handleFileSelect(e) {
  const files = Array.from(e.target.files);
  e.target.value = "";
  files.forEach((file) => {
    if (file.size > 25000) {
      alert(`File ${file.name} is too large. Strict API usage limits apply (max 25KB).`);
      return;
    }
    const reader = new FileReader();
    reader.onload = (ev) => {
      state.stagedFiles.push({ name: file.name, content: ev.target.result });
      renderStagedFiles();
    };
    reader.readAsText(file);
  });
}

function renderStagedFiles() {
  const container = el("stagedFiles");
  container.innerHTML = "";
  state.stagedFiles.forEach((f, i) => {
    const div = document.createElement("div");
    div.className = "staged-file";
    div.innerHTML = `<span><i class="ph ph-file-text"></i> ${f.name}</span><button class="staged-file-remove"><i class="ph ph-x"></i></button>`;
    div.querySelector("button").addEventListener("click", () => {
      state.stagedFiles.splice(i, 1);
      renderStagedFiles();
    });
    container.appendChild(div);
  });
  updateTokenUI();
}

function composeUserContent(text) {
  if (!text && state.stagedFiles.length === 0) return "";
  if (state.stagedFiles.length === 0) return text;
  let fileContext = "\n\nAttached Files:\n";
  state.stagedFiles.forEach((f) => {
    fileContext += `\n--- ${f.name} ---\n${f.content}\n`;
  });
  return (text || "Please analyze the attached files.") + fileContext;
}

async function sendMessage() {
  const input = el("promptInput");
  const text = input.value.trim();
  if ((!text && state.stagedFiles.length === 0) || state.streaming) return;

  const apiKey = apiKeyFor(state.settings, state.settings.provider);
  if (!apiKey) {
    alert("Add your API key in Settings first.");
    openSettings();
    return;
  }

  const contentToSave = composeUserContent(text);

  if (contentToSave.length > MAX_MESSAGE_CHARS) {
    alert("Message is too long. Please reduce text or attached files to comply with strict API usage limits.");
    return;
  }

  const chat = getActiveChat();
  chat.messages.push({ id: crypto.randomUUID(), role: "user", content: contentToSave, timestamp: Date.now() });

  if (chat.messages.length === 1) {
    chat.title = text ? text.slice(0, 42) + (text.length > 42 ? "…" : "") : "File Analysis";
    el("chatTitle").textContent = chat.title;
  }

  chat.updatedAt = Date.now();
  input.value = "";
  autoResize(input);
  state.stagedFiles = [];
  renderStagedFiles();

  await dbPut("chats", chat);
  renderChatList(el("searchChats").value);
  renderMessages(chat);
  runAssistantResponse(chat);
}

async function runAssistantResponse(chat, existing = null) {
  const provider = state.settings.provider;
  const apiKey = apiKeyFor(state.settings, provider);
  const model = PROVIDERS[provider].defaultModel;
  const temperature = parseFloat(chat.temperature ?? state.settings.temperature);
  const systemPrompt = resolveSystemPrompt(chat);

  const assistantMsg = existing || { id: crypto.randomUUID(), role: "assistant", content: "", timestamp: Date.now() };
  if (!existing) chat.messages.push(assistantMsg);

  const container = el("messages");
  let row = existing ? container.querySelector(`[data-id="${assistantMsg.id}"]`) : null;
  if (!row) {
    row = buildMessageEl(assistantMsg);
    container.appendChild(row);
  }
  const contentEl = row.querySelector(".msg-content");
  contentEl.innerHTML = `<span class="typing-dots"><span></span><span></span><span></span></span>`;
  container.scrollTop = container.scrollHeight;

  const recentMessages = chat.messages
    .filter((m) => m.content)
    .slice(-CONTEXT_MESSAGES)
    .map((m) => ({ role: m.role, content: m.content }));

  const payloadMessages = [{ role: "system", content: systemPrompt }].concat(recentMessages);

  setStreamingUI(true);
  state.abortController = new AbortController();
  let fullText = "";
  let reportedUsage = null;
  let errorMessage = "";

  try {
    const result = await streamChatCompletion({
      provider,
      apiKey,
      model,
      messages: payloadMessages,
      temperature,
      signal: state.abortController.signal,
      onDelta: (_delta, textSoFar) => {
        fullText = textSoFar;
        renderContentInto(contentEl, textSoFar);
        container.scrollTop = container.scrollHeight;
      }
    });
    fullText = result.text;
    reportedUsage = result.usage;
  } catch (err) {
    if (err.name !== "AbortError") {
      errorMessage = err.message;
      renderContentInto(contentEl, (fullText || "") + `\n\n**Error:** ${err.message}`);
    }
  }

  assistantMsg.content = fullText;
  assistantMsg.usage = fullText ? normalizeUsage(reportedUsage, estimatePayloadTokens(payloadMessages), fullText) : null;

  let reverted = false;
  if (!fullText && assistantMsg.versions && assistantMsg.versions.length > 1) {
    const idx = chat.messages.findIndex((m) => m.id === assistantMsg.id);
    const removed = assistantMsg.vIndex;
    assistantMsg.versions.splice(removed, 1);
    const tail = activateVersion(assistantMsg, Math.max(0, removed - 1));
    chat.messages = chat.messages.slice(0, idx + 1).concat(tail);
    reverted = true;
  }

  chat.updatedAt = Date.now();
  await dbPut("chats", chat);
  setStreamingUI(false);
  state.abortController = null;

  if (reverted) {
    if (chat.id === state.activeChatId) renderMessages(chat);
    if (errorMessage) alert("Retry failed: " + errorMessage);
  } else if (!errorMessage && row.isConnected) {
    const fresh = buildMessageEl(assistantMsg);
    fresh.classList.add("settled");
    row.replaceWith(fresh);
  }

  renderChatList(el("searchChats").value);
  updateTokenUI();
}

function estimateTokens(text) {
  return text ? Math.ceil(text.length / CHARS_PER_TOKEN) : 0;
}

function estimatePayloadTokens(messages) {
  return messages.reduce((sum, m) => sum + estimateTokens(m.content) + MESSAGE_OVERHEAD_TOKENS, 0);
}

function normalizeUsage(reported, promptEstimate, completionText) {
  if (reported && (reported.total_tokens || reported.completion_tokens)) {
    const prompt = reported.prompt_tokens || 0;
    const completion = reported.completion_tokens || 0;
    return { prompt, completion, total: reported.total_tokens || prompt + completion, estimated: false };
  }
  const completion = estimateTokens(completionText);
  return { prompt: promptEstimate, completion, total: promptEstimate + completion, estimated: true };
}

function resolveSystemPrompt(chat) {
  const persona = chat.personaId ? state.settings.personas.find((p) => p.id === chat.personaId) : null;
  if (persona) return persona.prompt;
  return chat.systemPrompt || state.settings.systemPrompt;
}

function updateTokenUI() {
  const hint = el("tokenHint");
  const pill = el("tokenPill");
  const chat = getActiveChat();
  if (!chat || !state.settings) {
    hint.textContent = "";
    pill.classList.add("hidden");
    return;
  }
  const draftText = composeUserContent(el("promptInput").value.trim());
  const history = chat.messages.filter((m) => m.content);
  const context = draftText ? history.slice(-(CONTEXT_MESSAGES - 1)) : history.slice(-CONTEXT_MESSAGES);
  const draftTokens = estimateTokens(draftText);
  const total = estimateTokens(resolveSystemPrompt(chat)) + MESSAGE_OVERHEAD_TOKENS + estimatePayloadTokens(context) + draftTokens;
  let text = `Next request ≈ ${fmt(total)} tokens`;
  if (draftText) text += ` · draft ≈ ${fmt(draftTokens)} · ${fmt(draftText.length)} / ${fmt(MAX_MESSAGE_CHARS)} characters`;
  hint.textContent = text;
  hint.classList.toggle("warn", draftText.length > MAX_MESSAGE_CHARS * 0.9);
  const used = chat.messages.reduce((sum, m) => sum + (m.usage ? m.usage.total : 0), 0);
  pill.textContent = `${fmt(used)} tokens used`;
  pill.classList.toggle("hidden", used === 0);
}

function updateChatChrome() {
  const chat = getActiveChat();
  const persona = chat && chat.personaId ? state.settings.personas.find((p) => p.id === chat.personaId) : null;
  el("personaLabel").textContent = persona ? persona.name : "Default";
  el("personaBtn").classList.toggle("custom", !!persona);
  updateTokenUI();
}

let activePopup = null;

function closePopup() {
  if (activePopup) {
    activePopup.remove();
    activePopup = null;
  }
}

function openPopup(anchor, items, { placement = "below", align = "left" } = {}) {
  closePopup();
  const menu = document.createElement("div");
  menu.className = "popup-menu";
  items.forEach((item) => {
    if (item.divider) {
      const line = document.createElement("div");
      line.className = "popup-divider";
      menu.appendChild(line);
      return;
    }
    const btn = document.createElement("button");
    btn.className = "popup-item" + (item.active ? " active" : "");
    btn.innerHTML = `<i class="ph ${item.icon || "ph-circle"}"></i><span class="popup-label"></span>${item.active ? '<i class="ph ph-check popup-check"></i>' : ""}`;
    btn.querySelector(".popup-label").textContent = item.label;
    btn.addEventListener("click", () => {
      closePopup();
      item.onClick();
    });
    menu.appendChild(btn);
  });
  document.body.appendChild(menu);

  const rect = anchor.getBoundingClientRect();
  const width = menu.offsetWidth;
  const height = menu.offsetHeight;
  let left = align === "right" ? rect.right - width : rect.left;
  left = Math.min(Math.max(8, left), window.innerWidth - width - 8);
  let top = placement === "above" ? rect.top - height - 8 : rect.bottom + 6;
  if (top + height > window.innerHeight - 8) top = rect.top - height - 6;
  top = Math.max(8, top);
  menu.style.left = left + "px";
  menu.style.top = top + "px";
  activePopup = menu;
}

async function setChatPersona(chat, personaId) {
  chat.personaId = personaId;
  await dbPut("chats", chat);
  updateChatChrome();
}

function openPersonaMenu(anchor) {
  const chat = getActiveChat();
  if (!chat) return;
  const current = chat.personaId && state.settings.personas.some((p) => p.id === chat.personaId) ? chat.personaId : null;
  const items = [{ label: "Default", icon: "ph-user-circle", active: !current, onClick: () => setChatPersona(chat, null) }];
  state.settings.personas.forEach((persona) => {
    items.push({ label: persona.name, icon: "ph-user-focus", active: current === persona.id, onClick: () => setChatPersona(chat, persona.id) });
  });
  items.push({ divider: true });
  items.push({ label: "Manage personas…", icon: "ph-gear", onClick: () => openLibrary("personas") });
  openPopup(anchor, items, { placement: "below", align: "right" });
}

function insertTemplate(template) {
  const input = el("promptInput");
  const start = input.selectionStart;
  const end = input.selectionEnd;
  input.value = input.value.slice(0, start) + template.text + input.value.slice(end);
  autoResize(input);
  input.focus();
  const placeholder = /\{\{[^}]+\}\}/.exec(template.text);
  if (placeholder) input.setSelectionRange(start + placeholder.index, start + placeholder.index + placeholder[0].length);
  else input.setSelectionRange(start + template.text.length, start + template.text.length);
  updateTokenUI();
}

function jumpToNextPlaceholder(input) {
  const pattern = /\{\{[^}]+\}\}/g;
  pattern.lastIndex = input.selectionEnd;
  const match = pattern.exec(input.value);
  if (!match) return false;
  input.setSelectionRange(match.index, match.index + match[0].length);
  return true;
}

function openTemplateMenu(anchor) {
  const items = state.settings.templates.map((template) => ({
    label: template.name,
    icon: "ph-text-aa",
    onClick: () => insertTemplate(template)
  }));
  if (items.length) items.push({ divider: true });
  items.push({ label: "Manage templates…", icon: "ph-gear", onClick: () => openLibrary("templates") });
  openPopup(anchor, items, { placement: "above" });
}

const library = { tab: "personas", editingId: null, creating: false };

function openLibrary(tab = "personas") {
  library.tab = tab;
  library.editingId = null;
  library.creating = false;
  el("libraryError").textContent = "";
  el("libraryModal").classList.remove("hidden");
  renderLibrary();
}

function closeLibrary() {
  el("libraryModal").classList.add("hidden");
}

function renderLibrary() {
  const isPersona = library.tab === "personas";
  el("tabPersonas").classList.toggle("active", isPersona);
  el("tabTemplates").classList.toggle("active", !isPersona);

  const entries = state.settings[library.tab];
  const list = el("libraryList");
  list.innerHTML = "";
  if (!entries.length) {
    const empty = document.createElement("div");
    empty.className = "library-empty";
    empty.textContent = isPersona ? "No personas yet." : "No templates yet.";
    list.appendChild(empty);
  }
  entries.forEach((entry) => {
    const row = document.createElement("div");
    row.className = "library-item";
    row.innerHTML = `
      <div class="library-item-main">
        <div class="library-item-name"></div>
        <div class="library-item-preview"></div>
      </div>
      <div class="library-item-actions">
        <button data-act="edit" title="Edit"><i class="ph ph-pencil-simple"></i></button>
        <button data-act="delete" title="Delete"><i class="ph ph-trash"></i></button>
      </div>
    `;
    row.querySelector(".library-item-name").textContent = entry.name;
    row.querySelector(".library-item-preview").textContent = isPersona ? entry.prompt : entry.text;
    row.querySelector('[data-act="edit"]').addEventListener("click", () => startLibraryEdit(entry.id));
    row.querySelector('[data-act="delete"]').addEventListener("click", () => deleteLibraryEntry(entry.id));
    list.appendChild(row);
  });

  const editing = library.creating || library.editingId !== null;
  el("libraryEditor").classList.toggle("hidden", !editing);
  el("libraryAddBtn").classList.toggle("hidden", editing);
  el("libraryTextLabel").textContent = isPersona ? "Instructions (max 500 characters)" : "Template text — use {{placeholder}} for fill-in spots";
  el("libraryText").maxLength = isPersona ? 500 : 4000;
}

function startLibraryCreate() {
  library.creating = true;
  library.editingId = null;
  el("libraryName").value = "";
  el("libraryText").value = "";
  el("libraryError").textContent = "";
  renderLibrary();
  el("libraryName").focus();
}

function startLibraryEdit(id) {
  const entry = state.settings[library.tab].find((e) => e.id === id);
  if (!entry) return;
  library.creating = false;
  library.editingId = id;
  el("libraryName").value = entry.name;
  el("libraryText").value = library.tab === "personas" ? entry.prompt : entry.text;
  el("libraryError").textContent = "";
  renderLibrary();
  el("libraryName").focus();
}

function cancelLibraryEdit() {
  library.creating = false;
  library.editingId = null;
  el("libraryError").textContent = "";
  renderLibrary();
}

async function saveLibraryEntry() {
  const isPersona = library.tab === "personas";
  const name = el("libraryName").value.trim();
  const text = el("libraryText").value.trim();
  if (!name || !text) {
    el("libraryError").textContent = "Name and text are both required.";
    return;
  }
  const field = isPersona ? "prompt" : "text";
  const entries = state.settings[library.tab];
  if (library.editingId !== null) {
    const entry = entries.find((e) => e.id === library.editingId);
    entry.name = name;
    entry[field] = text;
  } else {
    entries.push({ id: crypto.randomUUID(), name, [field]: text });
  }
  await dbPut("settings", state.settings);
  cancelLibraryEdit();
  updateChatChrome();
}

async function deleteLibraryEntry(id) {
  const entry = state.settings[library.tab].find((e) => e.id === id);
  if (!entry || !confirm(`Delete "${entry.name}"?`)) return;
  state.settings[library.tab] = state.settings[library.tab].filter((e) => e.id !== id);
  await dbPut("settings", state.settings);
  if (library.editingId === id) cancelLibraryEdit();
  else renderLibrary();
  updateChatChrome();
}

function chatToMarkdown(chat) {
  let mdText = `# ${chat.title}\n\n`;
  chat.messages.forEach((m) => {
    mdText += `**${m.role === "user" ? "You" : "Strata"}**:\n${m.content}\n\n---\n\n`;
  });
  return mdText;
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function exportActiveChat() {
  const chat = getActiveChat();
  if (!chat || !chat.messages.length) return;
  const safeTitle = chat.title.replace(/[^a-z0-9]/gi, "_").toLowerCase();
  downloadBlob(new Blob([chatToMarkdown(chat)], { type: "text/markdown" }), `${safeTitle}.md`);
}

function mergeById(existing, incoming) {
  if (!Array.isArray(incoming)) return existing;
  const ids = new Set(existing.map((e) => e.id));
  return existing.concat(incoming.filter((e) => e && e.id && !ids.has(e.id)));
}

async function verifyPassword(user, password) {
  const hash = await pbkdf2Hash(password, user.passwordSalt);
  return hash === user.passwordHash;
}

function formatJoinDate(ts) {
  const d = new Date(ts);
  return "Joined " + d.toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
}

function openAccount() {
  const user = state.user;
  el("accountAvatar").textContent = user.username.slice(0, 1).toUpperCase();
  el("accountUsername").textContent = user.username;
  el("accountCreated").textContent = formatJoinDate(user.createdAt);
  el("changePasswordForm").reset();
  el("changePasswordError").textContent = "";
  el("changePasswordSuccess").textContent = "";
  el("recoveryConfirmPassword").value = "";
  el("regenerateError").textContent = "";
  el("newAccountRecoveryDisplay").classList.add("hidden");
  el("newAccountRecoveryDisplay").textContent = "";
  el("deleteConfirmPassword").value = "";
  el("deleteAccountError").textContent = "";
  el("accountScreen").classList.remove("hidden");
}

function closeAccount() {
  el("accountScreen").classList.add("hidden");
}

async function handleChangePassword(e) {
  e.preventDefault();
  const errEl = el("changePasswordError");
  const okEl = el("changePasswordSuccess");
  errEl.textContent = "";
  okEl.textContent = "";

  const current = el("currentPasswordInput").value;
  const next = el("newPasswordInput").value;
  const confirm = el("confirmPasswordInput").value;

  const valid = await verifyPassword(state.user, current);
  if (!valid) {
    errEl.textContent = "Current password is incorrect.";
    return;
  }
  if (next !== confirm) {
    errEl.textContent = "New passwords don't match.";
    return;
  }
  if (next.length < 8) {
    errEl.textContent = "New password must be at least 8 characters.";
    return;
  }

  const passwordSalt = randomSaltHex();
  const passwordHash = await pbkdf2Hash(next, passwordSalt);
  state.user.passwordSalt = passwordSalt;
  state.user.passwordHash = passwordHash;
  await dbPut("users", state.user);
  el("changePasswordForm").reset();
  okEl.textContent = "Password updated.";
}

async function handleRegenerateRecovery() {
  const errEl = el("regenerateError");
  errEl.textContent = "";
  const password = el("recoveryConfirmPassword").value;
  const valid = await verifyPassword(state.user, password);
  if (!valid) {
    errEl.textContent = "Password is incorrect.";
    return;
  }
  const newRecoveryCode = generateRecoveryCode();
  const recoverySalt = randomSaltHex();
  const recoveryHash = await pbkdf2Hash(normalizeCode(newRecoveryCode), recoverySalt);
  state.user.recoverySalt = recoverySalt;
  state.user.recoveryHash = recoveryHash;
  await dbPut("users", state.user);
  el("recoveryConfirmPassword").value = "";
  const display = el("newAccountRecoveryDisplay");
  display.textContent = newRecoveryCode;
  display.classList.remove("hidden");
}

async function handleDeleteAccount() {
  const errEl = el("deleteAccountError");
  errEl.textContent = "";
  const password = el("deleteConfirmPassword").value;
  const valid = await verifyPassword(state.user, password);
  if (!valid) {
    errEl.textContent = "Password is incorrect.";
    return;
  }
  if (!confirm("This will permanently delete your account and all of your chats. Continue?")) return;

  const userId = state.user.id;
  const chats = await dbGetAllByIndex("chats", "userId", userId);
  for (const chat of chats) {
    await dbDelete("chats", chat.id);
  }
  await dbDelete("settings", userId);
  await dbDelete("users", userId);

  clearSession();
  resetState();
  closeAccount();
  showAuthPanel("loginPanel");
  showAuthScreen();
}

function wireAccountEvents() {
  el("accountBtn").addEventListener("click", openAccount);
  el("userPill").addEventListener("click", openAccount);
  el("backToChatBtn").addEventListener("click", closeAccount);
  el("changePasswordForm").addEventListener("submit", handleChangePassword);
  el("regenerateRecoveryBtn").addEventListener("click", handleRegenerateRecovery);
  el("deleteAccountBtn").addEventListener("click", handleDeleteAccount);
}

function openSettings() {
  el("settingsModal").classList.remove("hidden");
}

function closeSettings() {
  el("settingsModal").classList.add("hidden");
}

async function saveSettings() {
  const provider = el("providerSelect").value;
  const key = el("apiKeyInput").value.trim();
  state.settings.provider = provider;
  state.settings.apiKeyGroq = key;
  state.settings.temperature = parseFloat(el("temperatureInput").value);
  const promptVal = el("systemPromptInput").value;
  state.settings.systemPrompt = promptVal.length > 500 ? promptVal.substring(0, 500) : promptVal;
  await dbPut("settings", state.settings);
  closeSettings();
}

async function exportAllDataZip() {
  try {
    const zip = new JSZip();
    const userId = state.user.id;
    const userChats = await dbGetAllByIndex("chats", "userId", userId);

    const backupData = {
      version: 2,
      timestamp: Date.now(),
      chats: userChats,
      folders: state.settings.folders,
      personas: state.settings.personas,
      templates: state.settings.templates
    };
    zip.file("strata_backup.json", JSON.stringify(backupData, null, 2));

    const mdFolder = zip.folder("Readable_Chats");
    userChats.forEach((chat) => {
      const safeTitle = chat.title.replace(/[^a-z0-9]/gi, "_").toLowerCase();
      mdFolder.file(`${safeTitle}_${chat.id}.md`, chatToMarkdown(chat));
    });

    const blob = await zip.generateAsync({ type: "blob" });
    downloadBlob(blob, `Strata_Backup_${new Date().toISOString().slice(0, 10)}.zip`);
  } catch (err) {
    alert("Export failed: " + err.message);
  }
}

async function importAllDataZip(file) {
  try {
    const zip = await JSZip.loadAsync(file);
    const backupFile = zip.file("strata_backup.json") || zip.file("slate_backup.json");
    if (!backupFile) {
      alert("Invalid backup file. 'strata_backup.json' not found inside the ZIP.");
      return;
    }
    const jsonStr = await backupFile.async("string");
    const data = JSON.parse(jsonStr);
    
    if (data.chats && Array.isArray(data.chats)) {
      state.settings.folders = mergeById(state.settings.folders, data.folders);
      state.settings.personas = mergeById(state.settings.personas, data.personas);
      state.settings.templates = mergeById(state.settings.templates, data.templates);
      await dbPut("settings", state.settings);
      let importedCount = 0;
      for (const chat of data.chats) {
        delete chat.id; 
        chat.userId = state.user.id;
        await dbAdd("chats", chat);
        importedCount++;
      }
      
      state.chats = await dbGetAllByIndex("chats", "userId", state.user.id);
      state.chats.sort((a, b) => b.updatedAt - a.updatedAt);
      renderChatList();
      updateChatChrome();
      alert(`Successfully imported ${importedCount} chats!`);
      closeSettings();
    }
  } catch (err) {
    console.error(err);
    alert("Failed to import: " + err.message);
  }
}

async function copyWithFeedback(btn, text) {
  const original = btn.innerHTML;
  let ok = true;
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    ok = false;
  }
  btn.innerHTML = ok ? '<i class="ph ph-check"></i> Copied' : '<i class="ph ph-warning"></i> Copy failed';
  setTimeout(() => { btn.innerHTML = original; }, 1600);
}

const AUTH_PANELS = ["loginPanel", "signupPanel", "recoveryPanel", "forgotPanel", "newRecoveryPanel"];

function showAuthPanel(name) {
  AUTH_PANELS.forEach((id) => el(id).classList.toggle("hidden", id !== name));
  el("loginError").textContent = "";
  el("signupError").textContent = "";
  el("forgotError").textContent = "";
}

async function afterLogin(user) {
  state.user = user;
  setSessionUserId(user.id);
  state.settings = await loadUserSettings(user.id);

  applyTheme(state.settings.theme);

  el("providerSelect").value = state.settings.provider;
  el("apiKeyInput").value = apiKeyFor(state.settings, state.settings.provider);

  el("temperatureInput").value = state.settings.temperature;
  el("tempValue").textContent = state.settings.temperature;
  el("systemPromptInput").value = state.settings.systemPrompt;
  el("userNameLabel").textContent = user.username;
  el("userAvatar").textContent = user.username.slice(0, 1).toUpperCase();

  showAppScreen();

  state.chats = await dbGetAllByIndex("chats", "userId", user.id);
  state.chats.sort((a, b) => b.updatedAt - a.updatedAt);
  renderChatList();

  if (state.chats.length) selectChat(state.chats[0].id);
  else newChat();
}

async function tryRestoreSession() {
  const uid = getSessionUserId();
  if (!uid) return showAuthScreen();
  const user = await dbGet("users", uid);
  if (!user) {
    clearSession();
    return showAuthScreen();
  }
  await afterLogin(user);
}

function wireAuthEvents() {
  el("goSignup").addEventListener("click", () => showAuthPanel("signupPanel"));
  el("goForgot").addEventListener("click", () => showAuthPanel("forgotPanel"));
  el("goLoginFromSignup").addEventListener("click", () => showAuthPanel("loginPanel"));
  el("goLoginFromForgot").addEventListener("click", () => showAuthPanel("loginPanel"));

  el("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = el("loginUsername").value.trim();
    const password = el("loginPassword").value;
    try {
      const user = await loginUser(username, password);
      await afterLogin(user);
    } catch (err) {
      el("loginError").textContent = err.message;
    }
  });

  let pendingSignupId = null;
  el("signupForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = el("signupUsername").value.trim();
    const password = el("signupPassword").value;
    const confirm = el("signupConfirm").value;
    if (password !== confirm) {
      el("signupError").textContent = "Passwords don't match.";
      return;
    }
    try {
      const { id, recoveryCode } = await signUpUser(username, password);
      pendingSignupId = id;
      el("recoveryCodeDisplay").textContent = recoveryCode;
      showAuthPanel("recoveryPanel");
    } catch (err) {
      el("signupError").textContent = err.message;
    }
  });

  el("copyRecoveryBtn").addEventListener("click", (e) => {
    copyWithFeedback(e.currentTarget, el("recoveryCodeDisplay").textContent);
  });

  el("recoveryContinueBtn").addEventListener("click", async () => {
    const user = await dbGet("users", pendingSignupId);
    await afterLogin(user);
  });

  el("forgotForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = el("forgotUsername").value.trim();
    const code = el("forgotCode").value.trim();
    const newPassword = el("forgotNewPassword").value;
    try {
      const newCode = await resetPasswordWithCode(username, code, newPassword);
      el("newRecoveryCodeDisplay").textContent = newCode;
      showAuthPanel("newRecoveryPanel");
    } catch (err) {
      el("forgotError").textContent = err.message;
    }
  });

  el("copyNewRecoveryBtn").addEventListener("click", (e) => {
    copyWithFeedback(e.currentTarget, el("newRecoveryCodeDisplay").textContent);
  });

  el("newRecoveryContinueBtn").addEventListener("click", () => showAuthPanel("loginPanel"));
}

function wireAppChromeEvents() {
  el("newChatBtn").addEventListener("click", () => newChat());
  el("searchChats").addEventListener("input", (e) => renderChatList(e.target.value));
  el("menuToggle").addEventListener("click", () => el("sidebar").classList.toggle("open"));

  el("logoutBtn").addEventListener("click", () => {
    clearSession();
    resetState();
    showAuthPanel("loginPanel");
    showAuthScreen();
  });

  el("sendBtn").addEventListener("click", sendMessage);
  el("stopBtn").addEventListener("click", stopStreaming);
  
  el("attachBtn").addEventListener("click", () => el("fileInput").click());
  el("fileInput").addEventListener("change", handleFileSelect);

  const promptInput = el("promptInput");
  promptInput.addEventListener("input", () => {
    autoResize(promptInput);
    updateTokenUI();
  });
  promptInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    } else if (e.key === "Tab" && !e.shiftKey && jumpToNextPlaceholder(promptInput)) {
      e.preventDefault();
    }
  });
}

function wireExtraEvents() {
  el("newFolderBtn").addEventListener("click", () => promptCreateFolder());
  el("personaBtn").addEventListener("click", (e) => openPersonaMenu(e.currentTarget));
  el("templateBtn").addEventListener("click", (e) => openTemplateMenu(e.currentTarget));
  el("exportChatBtn").addEventListener("click", exportActiveChat);

  el("libraryBtn").addEventListener("click", () => openLibrary("personas"));
  el("closeLibrary").addEventListener("click", closeLibrary);
  el("tabPersonas").addEventListener("click", () => openLibrary("personas"));
  el("tabTemplates").addEventListener("click", () => openLibrary("templates"));
  el("libraryAddBtn").addEventListener("click", startLibraryCreate);
  el("librarySaveBtn").addEventListener("click", saveLibraryEntry);
  el("libraryCancelBtn").addEventListener("click", cancelLibraryEdit);

  document.addEventListener("mousedown", (e) => {
    if (activePopup && !activePopup.contains(e.target)) closePopup();
  });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      if (el("appScreen").classList.contains("hidden")) return;
      e.preventDefault();
      el("sidebar").classList.add("open");
      el("searchChats").focus();
    } else if (e.key === "Escape") {
      closePopup();
      if (!el("libraryModal").classList.contains("hidden")) closeLibrary();
    }
  });
}

function wireSettingsEvents() {
  el("settingsBtn").addEventListener("click", openSettings);
  el("closeSettings").addEventListener("click", closeSettings);
  el("saveSettingsBtn").addEventListener("click", saveSettings);

  el("providerSelect").addEventListener("change", (e) => {
    el("apiKeyInput").value = apiKeyFor(state.settings, e.target.value);
  });

  el("temperatureInput").addEventListener("input", (e) => {
    el("tempValue").textContent = e.target.value;
  });

  el("themeDark").addEventListener("click", async () => {
    applyTheme("dark");
    state.settings.theme = "dark";
    await dbPut("settings", state.settings);
  });

  el("themeLight").addEventListener("click", async () => {
    applyTheme("light");
    state.settings.theme = "light";
    await dbPut("settings", state.settings);
  });

  el("exportZipBtn").addEventListener("click", exportAllDataZip);
  
  el("importZipBtn").addEventListener("click", () => el("importZipInput").click());
  el("importZipInput").addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      importAllDataZip(e.target.files[0]);
    }
    e.target.value = "";
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  marked.setOptions({ breaks: true, gfm: true });
  await openDB();

  wireAuthEvents();
  wireAppChromeEvents();
  wireSettingsEvents();
  wireAccountEvents();
  wireExtraEvents();

  await tryRestoreSession();
});