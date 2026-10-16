"use strict";
// Entrance web UI: WebAuthn passkey auth, host list, and an xterm terminal
// bridged over WebSocket to the agent's PTY.

const $ = (id) => document.getElementById(id);

// --- base64 helpers (Go marshals []byte as standard base64) ---------------
function bufToB64(buf) {
	const bytes = new Uint8Array(buf);
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}
function b64ToBuf(s) {
	const bin = atob(s);
	const bytes = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
	return bytes.buffer;
}
function b64urlToBuf(s) {
	s = s.replace(/-/g, "+").replace(/_/g, "/");
	while (s.length % 4) s += "=";
	return b64ToBuf(s);
}
function bufToB64url(buf) {
	return bufToB64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function strToB64(s) {
	const bytes = new TextEncoder().encode(s);
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin);
}
function b64ToStr(s) {
	const bin = atob(s);
	const bytes = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
	return new TextDecoder().decode(bytes);
}

async function post(url, body, headers) {
	const res = await fetch(url, {
		method: "POST",
		headers: Object.assign({ "Content-Type": "application/json" }, headers || {}),
		body: body ? JSON.stringify(body) : undefined,
		credentials: "same-origin",
	});
	if (!res.ok) throw new Error((await res.text()).trim() || res.statusText);
	const ct = res.headers.get("content-type") || "";
	return ct.includes("json") ? res.json() : null;
}

// --- WebAuthn -------------------------------------------------------------
async function register() {
	const token = $("bootstrap-token").value.trim();
	if (!token) throw new Error("enter the bootstrap token first");
	const options = await post("/webauthn/register/begin", null, { "X-Bootstrap-Token": token });
	const pk = options.publicKey;
	pk.challenge = b64urlToBuf(pk.challenge);
	pk.user.id = b64urlToBuf(pk.user.id);
	if (pk.excludeCredentials) for (const c of pk.excludeCredentials) c.id = b64urlToBuf(c.id);

	const cred = await navigator.credentials.create({ publicKey: pk });
	const body = {
		id: cred.id,
		rawId: bufToB64url(cred.rawId),
		type: cred.type,
		response: {
			clientDataJSON: bufToB64url(cred.response.clientDataJSON),
			attestationObject: bufToB64url(cred.response.attestationObject),
			transports: cred.response.getTransports ? cred.response.getTransports() : [],
		},
		clientExtensionResults: cred.getClientExtensionResults(),
	};
	await post("/webauthn/register/finish", body, { "X-Bootstrap-Token": token });
	await boot();
}

async function login() {
	const options = await post("/webauthn/login/begin");
	const pk = options.publicKey;
	pk.challenge = b64urlToBuf(pk.challenge);
	if (pk.allowCredentials) for (const c of pk.allowCredentials) c.id = b64urlToBuf(c.id);

	const cred = await navigator.credentials.get({ publicKey: pk });
	const body = {
		id: cred.id,
		rawId: bufToB64url(cred.rawId),
		type: cred.type,
		response: {
			clientDataJSON: bufToB64url(cred.response.clientDataJSON),
			authenticatorData: bufToB64url(cred.response.authenticatorData),
			signature: bufToB64url(cred.response.signature),
			userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : null,
		},
		clientExtensionResults: cred.getClientExtensionResults(),
	};
	await post("/webauthn/login/finish", body);
	await boot();
}

async function logout() {
	try { await post("/logout"); } catch (e) { /* ignore */ }
	showAuth();
}

// --- hosts + terminal -----------------------------------------------------
let term = null;
let fit = null;
let ws = null;

function initTerm() {
	if (term) return;
	term = new Terminal({
		cursorBlink: true,
		fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
		fontSize: 14,
		theme: { background: "#0b0e14", foreground: "#d7dde7" },
	});
	fit = new FitAddon.FitAddon();
	term.loadAddon(fit);
	term.open($("terminal"));
	fit.fit();
	term.onData((d) => {
		if (ws && ws.readyState === WebSocket.OPEN) {
			ws.send(JSON.stringify({ t: "shell_data", data: strToB64(d) }));
		}
	});
	window.addEventListener("resize", () => { if (fit) { fit.fit(); sendResize(); } });
}

function sendResize() {
	if (ws && ws.readyState === WebSocket.OPEN && term) {
		ws.send(JSON.stringify({ t: "shell_resize", cols: term.cols, rows: term.rows }));
	}
}

function connect(host) {
	initTerm();
	if (ws) { ws.close(); ws = null; }
	$("term-host").textContent = host;
	$("term-close").hidden = false;
	term.clear();
	term.reset();
	const scheme = location.protocol === "https:" ? "wss" : "ws";
	ws = new WebSocket(`${scheme}://${location.host}/ws/shell/${encodeURIComponent(host)}?cols=${term.cols}&rows=${term.rows}`);
	ws.onmessage = (ev) => {
		let m;
		try { m = JSON.parse(ev.data); } catch (e) { return; }
		if (m.t === "shell_data" && m.data) term.write(b64ToStr(m.data));
		else if (m.t === "shell_exit") term.write("\r\n[process exited]\r\n");
		else if (m.t === "error") term.write("\r\n[error: " + (m.error || "") + "]\r\n");
	};
	ws.onclose = () => term.write("\r\n[disconnected]\r\n");
	ws.onopen = () => { fit.fit(); sendResize(); term.focus(); };
}

async function loadHosts() {
	const res = await fetch("/api/hosts", { credentials: "same-origin" });
	if (res.status === 401) return false;
	const hosts = await res.json();
	const ul = $("hosts");
	ul.innerHTML = "";
	if (!hosts.length) {
		const li = document.createElement("li");
		li.className = "offline";
		li.textContent = "No hosts yet. Start an agent.";
		ul.appendChild(li);
	}
	for (const h of hosts) {
		const li = document.createElement("li");
		li.className = h.online ? "online" : "offline";
		const dot = document.createElement("span"); dot.className = "dot";
		const name = document.createElement("span"); name.className = "name"; name.textContent = h.name;
		const meta = document.createElement("span"); meta.className = "meta"; meta.textContent = (h.os || "") + (h.arch ? "/" + h.arch : "");
		li.append(dot, name, meta);
		if (h.online) li.onclick = () => connect(h.name);
		ul.appendChild(li);
	}
	return true;
}

function showAuth() {
	$("app").hidden = true;
	$("auth").hidden = false;
	$("logout-btn").hidden = true;
}
function showApp() {
	$("auth").hidden = true;
	$("app").hidden = false;
	$("logout-btn").hidden = false;
}

async function boot() {
	const ok = await loadHosts();
	if (ok) showApp(); else showAuth();
}

window.addEventListener("DOMContentLoaded", () => {
	$("login-btn").onclick = () => login().catch((e) => ($("auth-msg").textContent = e.message));
	$("register-btn").onclick = () => register().catch((e) => ($("auth-msg").textContent = e.message));
	$("logout-btn").onclick = logout;
	$("term-close").onclick = () => { if (ws) ws.close(); };
	boot();
});
