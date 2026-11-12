// BCS Reports Dashboard
// A zoomable 3D view over the BCS Reports Hub feed.
//   overview  -> one card per department; zoom into a card to enter it
//   room      -> that department's reports as a wall of live HTML screens
//   focus     -> one report, full size and interactive
// Data comes from the Reports Hub (same GitHub Pages origin). The hub pages are
// StatiCrypt-encrypted; this page decrypts them in the browser with the same
// password, and never stores report content anywhere.

import * as THREE from 'three';
import { CSS3DRenderer, CSS3DObject } from './CSS3DRenderer.js';

// ----------------------------------------------------------------------------
// config
// ----------------------------------------------------------------------------
const HUB_BASE = new URL(document.documentElement.dataset.hub || '../bcs-reports-hub/', location.href).href;
const LS_PASS = 'staticrypt_passphrase';      // shared with the hub's "remember me"
const LS_EXP = 'staticrypt_expiration';
const REMEMBER_DAYS = 30;
const REFRESH_MS = 5 * 60 * 1000;

const DEPT_META = {
  castle: { label: 'Command', color: '#ec2a86' },
  finance: { label: 'Finance', color: '#f59e0b' },
  sales: { label: 'Sales', color: '#ff5d5d' },
  marketing: { label: 'Marketing', color: '#a855f7' },
  emails: { label: 'Comms', color: '#4f6ff5' },
  implementations: { label: 'Implementations', color: '#19b5d8' },
  support: { label: 'Support', color: '#14c8a4' },
};
const ASSISTANT = { id: 'assistant', label: 'Personal Assistant', color: '#dbe4ff' };
const OUTBOUND_BOARD_URL = 'https://dgubbay.github.io/bcs-outbound-board/';
const OUTBOUND = { id: 'outbound', label: 'Outbound', color: '#00B7D1', virtual: true, live: true };
const OUTBOUND_PANELS = [
  { key: 'board', title: 'This week' },
  { key: '30d', title: '30 days' },
  { key: 'leads', title: 'Leads' },
  { key: 'outbound', title: 'Outbound meetings' },
  { key: 'newdeals', title: 'New opportunities' },
  { key: 'wins', title: 'Closed won' },
  { key: 'quota', title: 'Quota' },
  { key: 'thisq', title: 'Q4 pipeline' },
  { key: 'nextq', title: 'Q1 pipeline' },
];
const FALLBACK_COLORS = ['#5b8def', '#d98a2b', '#3fae8f', '#c05ad6', '#d65a7a', '#7fa33a'];

const $ = (id) => document.getElementById(id);
const els = {
  stage: $('stage'), fade: $('fade'), hud: $('hud'), hint: $('hint'), toast: $('toast'),
  crumbHome: $('crumb-home'), crumbDept: $('crumb-dept'), sepDept: $('sep-dept'),
  status: $('feed-status'), btnRefresh: $('btn-refresh'), btnLock: $('btn-lock'),
  focus: $('focus'), focusFrame: $('focus-frame'), focusBack: $('focus-back'), focusTitle: $('focus-title'),
  focusPrev: $('focus-prev'), focusNext: $('focus-next'), focusPos: $('focus-pos'), focusOpen: $('focus-open'),
  gate: $('gate'), gateForm: $('gate-form'), gatePass: $('gate-pass'), gateRemember: $('gate-remember'),
  gateSubmit: $('gate-submit'), gateErr: $('gate-err'), gateMsg: $('gate-msg'), loading: $('loading'),
};
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
const coarse = matchMedia('(pointer: coarse)').matches;

// ----------------------------------------------------------------------------
// feed: fetch + decrypt (StatiCrypt-compatible: PBKDF2 -> HMAC-SHA256 check -> AES-CBC)
// ----------------------------------------------------------------------------
const enc = new TextEncoder();
const dec = new TextDecoder();
const hexToBytes = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
};
const bytesToHex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');

async function pbkdf2(password, salt, iterations, hash) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash, iterations, salt: enc.encode(salt) }, key, 256);
  return bytesToHex(bits);
}
async function hashPassword(password, salt) {
  let h = await pbkdf2(password, salt, 1000, 'SHA-1');
  h = await pbkdf2(h, salt, 14000, 'SHA-256');
  return pbkdf2(h, salt, 585000, 'SHA-256');
}
/** Returns the decrypted text, or null when the key does not match. */
async function decode(signedMsg, hashedHex) {
  const hmac = signedMsg.slice(0, 64);
  const msg = signedMsg.slice(64);
  let keyBytes;
  try { keyBytes = hexToBytes(hashedHex); } catch (_) { return null; }
  if (keyBytes.length !== 32) return null;
  const signKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = bytesToHex(await crypto.subtle.sign('HMAC', signKey, enc.encode(msg)));
  if (sig !== hmac) return null;
  const aesKey = await crypto.subtle.importKey('raw', keyBytes, 'AES-CBC', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: hexToBytes(msg.slice(0, 32)) }, aesKey, hexToBytes(msg.slice(32)));
  return dec.decode(plain);
}

function extractCipher(page) {
  const m = page.match(/"staticryptEncryptedMsgUniqueVariableName"\s*:\s*"([0-9a-f]+)"/);
  const s = page.match(/"staticryptSaltUniqueVariableName"\s*:\s*"([0-9a-f]+)"/);
  if (!m || !s) throw new Error('feed-format');
  return { msg: m[1], salt: s[1] };
}
function parseManifest(html) {
  const k = html.indexOf('window.HUB_MANIFEST');
  const start = k < 0 ? -1 : html.indexOf('{', k);
  if (start < 0) throw new Error('feed-format');
  let depth = 0, inStr = false, esc = false;
  for (let i = start; i < html.length; i++) {
    const c = html[i];
    if (inStr) {
      if (esc) esc = false; else if (c === '\\') esc = true; else if (c === '"') inStr = false;
    } else if (c === '"') inStr = true;
    else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return JSON.parse(html.slice(start, i + 1));
  }
  throw new Error('feed-format');
}
async function fetchText(url) {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error('http-' + res.status);
  return res.text();
}

// Live outbound TV board: public page at OUTBOUND_BOARD_URL, already split into
// hash-pinned slides. We fetch the HTML (CORS is open) and render each slide as
// a static srcdoc panel, then refresh on the same 5-minute cadence as the feed.
const outboundCache = { html: '', updated: '', fetchedAt: 0 };
function parseOutboundUpdated(html) {
  const m = html.match(/updated\s*<b>([^<]+)<\/b>\s*(MT)?/i);
  if (!m) return '';
  return (m[1].trim() + (m[2] ? ' MT' : '')).trim();
}
function prepareOutboundPanel(html, key) {
  let out = html.replace(/<meta\s+http-equiv=["']refresh["'][^>]*>/i, '');
  out = out.replace(/<script\b[\s\S]*?<\/script>/gi, '');
  out = out.replace(/<section\s+class="slide([^"]*)"([^>]*)>/g, (tag, cls, rest) => {
    const km = /data-key="([^"]+)"/.exec(tag);
    const on = km && km[1] === key;
    const classes = ('slide' + cls.replace(/\bactive\b/g, '') + (on ? ' active' : '')).replace(/\s+/g, ' ').trim();
    return `<section class="${classes}"${rest}>`;
  });
  const inject = `<base href="${OUTBOUND_BOARD_URL}"><style>#nav,#prog,#stale{display:none!important}html,body{overflow:hidden!important}</style>`;
  if (/<head[^>]*>/i.test(out)) return out.replace(/<head[^>]*>/i, (h) => h + inject);
  return inject + out;
}
async function loadOutboundBoard() {
  const html = await fetchText(OUTBOUND_BOARD_URL);
  outboundCache.html = html;
  outboundCache.updated = parseOutboundUpdated(html);
  outboundCache.fetchedAt = Date.now();
  const d = depts.find((x) => x.live);
  if (d) for (const r of d.reports) r.updated = outboundCache.updated;
  return outboundCache;
}

let hashed = null;          // hex key derived from the password
let hubCipher = null;       // { msg, salt } of the hub index
const reportHtml = new Map();   // href -> Promise<string>

function readRemembered() {
  try {
    const exp = localStorage.getItem(LS_EXP);
    if (exp && Date.now() > parseInt(exp, 10)) return null;
    return localStorage.getItem(LS_PASS);
  } catch (_) { return null; }
}
function remember(h) {
  try {
    localStorage.setItem(LS_PASS, h);
    localStorage.setItem(LS_EXP, String(Date.now() + REMEMBER_DAYS * 864e5));
  } catch (_) {}
}

/** Fetches the hub index and returns the manifest, or throws Error('locked'). */
async function loadManifest() {
  hubCipher = extractCipher(await fetchText(HUB_BASE + 'index.html'));
  if (!hashed) throw new Error('locked');
  const html = await decode(hubCipher.msg, hashed);
  if (html == null) throw new Error('locked');
  return parseManifest(html);
}
function loadReportHtml(report) {
  if (!reportHtml.has(report.href)) {
    const p = (async () => {
      const { msg } = extractCipher(await fetchText(new URL(report.href, HUB_BASE).href));
      const html = await decode(msg, hashed);
      if (html == null) throw new Error('locked');
      return html;
    })();
    p.catch(() => reportHtml.delete(report.href));
    reportHtml.set(report.href, p);
  }
  return reportHtml.get(report.href);
}
/** Adds a <base> so relative links resolve against the hub; previews also hide scrollbars. */
function prepareHtml(html, report, preview) {
  const base = `<base href="${new URL(report.href, HUB_BASE).href}" target="_blank">`;
  const extra = preview ? '<style>html{overflow:hidden!important}::-webkit-scrollbar{display:none}</style>' : '';
  if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, (m) => m + base + extra);
  return base + extra + html;
}

// ----------------------------------------------------------------------------
// data model
// ----------------------------------------------------------------------------
let depts = [];
let manifestStamp = '';
let feedDay = '';

const byNewest = (a, b) => (b.date || '').localeCompare(a.date || '') || (a.title || '').localeCompare(b.title || '');
const isAssistantReport = (r) => /personal\s*assistant/i.test(r.bot || '');
const isAssistantLand = (land) => /^(assistant|personal[-_ ]?assistant|digests?)$/i.test(land.id || '') || /personal\s*assistant|digest/i.test(land.name || '');
/** Every report once, even when it shows in both its department and the Personal Assistant section. */
function uniqueReports(list = depts) {
  const seen = new Map();
  for (const d of list) {
    if (d.live) continue;
    for (const r of d.reports) seen.set(r.href, r);
  }
  return [...seen.values()];
}
function outboundDept() {
  return {
    id: OUTBOUND.id,
    label: OUTBOUND.label,
    color: OUTBOUND.color,
    virtual: true,
    live: true,
    reports: OUTBOUND_PANELS.map((s) => ({
      href: `${OUTBOUND_BOARD_URL}#${s.key}`,
      title: s.title,
      key: s.key,
      bot: 'Outbound Board',
      live: true,
      updated: outboundCache.updated || '',
    })),
    newCount: 0,
  };
}

function buildDepts(manifest) {
  const lands = manifest.lands || [];
  const out = lands.filter((land) => !isAssistantLand(land)).map(deptFromLand());
  // Personal Assistant: every digest the assistant wrote, wherever the feed filed it,
  // plus anything the feed publishes under a dedicated assistant/digest section.
  const picked = new Map();
  for (const land of lands) {
    for (const r of land.reports || []) if (isAssistantLand(land) || isAssistantReport(r)) picked.set(r.href, r);
  }
  const reports = [...picked.values()].sort(byNewest);
  out.unshift({ id: ASSISTANT.id, label: ASSISTANT.label, color: ASSISTANT.color, virtual: true, reports, newCount: reports.filter((r) => r.isNew).length });
  const outbound = outboundDept();
  const salesIdx = out.findIndex((d) => d.id === 'sales');
  if (salesIdx >= 0) out.splice(salesIdx + 1, 0, outbound);
  else out.push(outbound);
  return out;
}
function deptFromLand() {
  let fallback = 0;
  return (land) => {
    const meta = DEPT_META[land.id] || {
      label: String(land.name || land.id).replace(/\s+Land$/i, ''),
      color: FALLBACK_COLORS[fallback++ % FALLBACK_COLORS.length],
    };
    const reports = [...(land.reports || [])].sort(byNewest);
    return { id: land.id, label: meta.label, color: meta.color, reports, newCount: reports.filter((r) => r.isNew).length };
  };
}
const parseDate = (iso) => {
  const [y, m, d] = String(iso || '').split('-').map(Number);
  return y ? new Date(y, (m || 1) - 1, d || 1) : null;
};
const fmtShort = (iso) => { const d = parseDate(iso); return d ? d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : ''; };
const fmtLong = (iso) => { const d = parseDate(iso); return d ? d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' }) : ''; };
function fmtStamp(s) {
  const d = s ? new Date(s) : null;
  if (!d || isNaN(d)) return '';
  return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
}
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

// ----------------------------------------------------------------------------
// 3D stage
// ----------------------------------------------------------------------------
const FOV = 40;
const TAN = Math.tan(THREE.MathUtils.degToRad(FOV / 2));
const CARD_W = 580, CARD_H = 380, CARD_GX = 80, CARD_GY = 80, OV_RADIUS = 3400;
const SCREEN_W = 1040, SCREEN_H = 718, SCREEN_S = 0.62, SCR_GX = 70, SCR_GY = 80, ROOM_RADIUS = 4200;
const ROOM_Z = -9000;
const FLOOR_Y = -760;

let W = innerWidth, H = innerHeight;
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(FOV, W / H, 10, 60000);
const cam = { pos: new THREE.Vector3(0, 0, 3000), goal: new THREE.Vector3(0, 0, 3000) };

let gl = null;
try {
  gl = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' });
  gl.setPixelRatio(Math.min(devicePixelRatio || 1, 2));
  gl.setClearColor(0x000000, 0);
  els.stage.appendChild(gl.domElement);
} catch (_) { gl = null; }
const css = new CSS3DRenderer();
els.stage.appendChild(css.domElement);
css.domElement.addEventListener('scroll', () => { css.domElement.scrollTop = 0; css.domElement.scrollLeft = 0; });

const overview = new THREE.Group();
const room = new THREE.Group();
room.position.z = ROOM_Z;
room.visible = false;
scene.add(overview, room);

// ambience (WebGL only): grid floor, a flowing starfield, drifting nebulae,
// a soft light beam under each card, a glow behind the active wall
const floorColor = new THREE.Color('#9a4dff');
const floorTarget = new THREE.Color('#9a4dff');
const uTime = { value: 0 };                 // shared clock for every shader
const flow = new THREE.Vector3();           // how far the starfield has drifted
const STAR_BOX = new THREE.Vector3(18000, 11000, 18000);
let warp = 0, warpTarget = 0, warpDir = 1;  // star rush + lens kick while flying between levels
let floorMat = null, starMat = null, roomGlow = null, roomPad = null, glowTex = null;
const nebulae = [];
const PLANE = new THREE.PlaneGeometry(1, 1);
const UV_VERT = `varying vec2 vUv; void main(){ vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`;

/** Soft light cone rising from the floor to the card. */
function beamMaterial(color, seed) {
  return new THREE.ShaderMaterial({
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, side: THREE.DoubleSide,
    uniforms: { uColor: { value: new THREE.Color(color) }, uTime, uSeed: { value: seed } },
    vertexShader: UV_VERT,
    fragmentShader: `uniform vec3 uColor; uniform float uTime; uniform float uSeed; varying vec2 vUv;
      void main(){
        float x = abs(vUv.x - 0.5) * 2.0;
        float w = mix(0.3, 1.0, vUv.y);
        float side = smoothstep(w, w * 0.15, x);
        float a = side * (0.035 + 0.2 * pow(1.0 - vUv.y, 1.6));
        a *= 0.8 + 0.2 * sin(uTime * 2.3 + uSeed * 20.0);
        a *= 0.78 + 0.22 * sin(vUv.y * 46.0 - uTime * 3.2);
        gl_FragColor = vec4(mix(uColor, vec3(1.0), 0.15), a);
      }`,
  });
}

if (gl) {
  floorMat = new THREE.ShaderMaterial({
    transparent: true, depthWrite: false,
    uniforms: { uColor: { value: floorColor }, uCam: { value: new THREE.Vector3() }, uTime, uCenterZ: { value: 0 } },
    vertexShader: `varying vec3 vW; void main(){ vec4 w = modelMatrix * vec4(position, 1.0); vW = w.xyz; gl_Position = projectionMatrix * viewMatrix * w; }`,
    fragmentShader: `uniform vec3 uColor; uniform vec3 uCam; uniform float uTime; uniform float uCenterZ; varying vec3 vW;
      float grid(vec2 p, float s){ vec2 q = p / s; vec2 g = abs(fract(q - 0.5) - 0.5) / fwidth(q); return 1.0 - min(min(g.x, g.y), 1.0); }
      void main(){
        float d = distance(vW.xz, uCam.xz);
        float fade = smoothstep(7500.0, 900.0, d);
        float a = grid(vW.xz, 220.0) * 0.5 + grid(vW.xz, 1100.0) * 0.7;
        gl_FragColor = vec4(mix(uColor, vec3(1.0), 0.25), a * fade * 0.55);
      }`,
  });
  const floor = new THREE.Mesh(new THREE.PlaneGeometry(60000, 60000), floorMat);
  floor.rotation.x = -Math.PI / 2;
  floor.position.y = FLOOR_Y;
  scene.add(floor);

  // starfield: an endless box of stars wrapped around the camera, twinkling and drifting past
  const N = coarse ? 1800 : 3200;
  const pos = new Float32Array(N * 3), seeds = new Float32Array(N), sizes = new Float32Array(N);
  for (let i = 0; i < N; i++) {
    pos[i * 3] = Math.random() * STAR_BOX.x;
    pos[i * 3 + 1] = Math.random() * STAR_BOX.y;
    pos[i * 3 + 2] = Math.random() * STAR_BOX.z;
    seeds[i] = Math.random();
    sizes[i] = 1.1 + Math.pow(Math.random(), 3) * 3.4;
  }
  const starGeo = new THREE.BufferGeometry();
  starGeo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
  starGeo.setAttribute('aSeed', new THREE.BufferAttribute(seeds, 1));
  starGeo.setAttribute('aSize', new THREE.BufferAttribute(sizes, 1));
  starMat = new THREE.ShaderMaterial({
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    uniforms: { uTime, uFlow: { value: flow }, uCam: { value: new THREE.Vector3() }, uBox: { value: STAR_BOX }, uScale: { value: 800 }, uTint: { value: floorColor }, uFloor: { value: FLOOR_Y }, uWarp: { value: 0 } },
    vertexShader: `attribute float aSeed; attribute float aSize;
      uniform float uTime; uniform vec3 uFlow; uniform vec3 uCam; uniform vec3 uBox; uniform float uScale; uniform float uFloor; uniform float uWarp;
      varying float vA; varying float vSeed;
      void main(){
        vec3 p = mod(position + uFlow - uCam, uBox) - 0.5 * uBox + uCam;
        vec4 mv = viewMatrix * vec4(p, 1.0);
        float d = -mv.z;
        float tw = 0.62 + 0.38 * sin(uTime * (0.7 + aSeed * 2.6) + aSeed * 40.0);
        vA = mix(tw, 1.0, uWarp) * smoothstep(200.0, 1500.0, d) * (1.0 - smoothstep(uBox.z * 0.32, uBox.z * 0.5, d)) * step(uFloor, p.y);
        vSeed = aSeed;
        gl_PointSize = clamp(aSize * uScale * (5.0 + 6.0 * uWarp) / d, 1.6, 9.0);
        gl_Position = projectionMatrix * mv;
      }`,
    fragmentShader: `uniform vec3 uTint; varying float vA; varying float vSeed;
      void main(){
        float r = length(gl_PointCoord - 0.5);
        float a = smoothstep(0.5, 0.0, r);
        vec3 col = mix(vec3(0.8, 0.9, 1.0), vec3(1.0, 0.88, 0.74), step(0.82, vSeed));
        col = mix(col, mix(uTint, vec3(1.0), 0.3), 0.6 * step(vSeed, 0.28));
        gl_FragColor = vec4(col, a * a * vA);
      }`,
  });
  const stars = new THREE.Points(starGeo, starMat);
  stars.frustumCulled = false;
  scene.add(stars);

  const c = document.createElement('canvas');
  c.width = c.height = 256;
  const g = c.getContext('2d');
  const grad = g.createRadialGradient(128, 128, 0, 128, 128, 128);
  grad.addColorStop(0, 'rgba(255,255,255,0.9)');
  grad.addColorStop(0.4, 'rgba(255,255,255,0.28)');
  grad.addColorStop(1, 'rgba(255,255,255,0)');
  g.fillStyle = grad;
  g.fillRect(0, 0, 256, 256);
  glowTex = new THREE.CanvasTexture(c);

  // nebulae: huge soft clouds far behind everything, slowly drifting and breathing
  scene.add(camera);
  [['#d81b84', -10500, 4200, 22000], ['#4450e0', 1500, 2200, 20000], ['#12a6c4', 11000, -1800, 20000]].forEach(([color, x, y, size], i) => {
    const s = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color, transparent: true, opacity: 0.1, depthWrite: false, depthTest: false, blending: THREE.AdditiveBlending }));
    s.scale.set(size, size * 0.62, 1);
    s.position.set(x, y, -30000);
    s.renderOrder = -10;
    s.userData = { x, y, i };
    camera.add(s);
    nebulae.push(s);
  });

  roomGlow = new THREE.Sprite(new THREE.SpriteMaterial({ map: glowTex, color: 0x9a4dff, transparent: true, opacity: 0.32, depthWrite: false, blending: THREE.AdditiveBlending }));
  roomGlow.scale.set(7000, 3600, 1);
  roomGlow.position.set(0, 100, -700);
  room.add(roomGlow);
}

// ----------------------------------------------------------------------------
// state
// ----------------------------------------------------------------------------
let mode = 'overview';      // 'overview' | 'room' | 'focus'
let busy = false;           // a camera transition is running
let current = null;         // department whose room is open
let focusIdx = -1;
const ov = { w: 0, h: 0, home: 3000, enter: 700 };
const rm = { w: 0, h: 0, home: 2000, focus: 700, cy: 0, tall: false, screens: [], surround: false, radius: 0, viewDist: 1 };
const look = { yaw: 0, pitch: 0, gy: 0, gp: 0 };
const MAX_PITCH = THREE.MathUtils.degToRad(42);
const isSurround = () => mode === 'room' && rm.surround;
const resetLook = () => { look.yaw = look.pitch = look.gy = look.gp = 0; };

const planeZ = () => (mode === 'overview' ? 0 : ROOM_Z);
/** Camera distance that fits a w x h curved grid, allowing for its edges bending toward the viewer. */
const fitDistance = (w, h, radius, pad = 1.2) => Math.max(h / 2 / TAN, w / 2 / (TAN * (W / H))) * pad + radius * (1 - Math.cos(w / 2 / radius));
/** Distance at which a w x h panel fills `fh` of the viewport height or `fw` of its width. */
const fillDistance = (w, h, fh, fw) => Math.max(h / 2 / TAN / fh, w / 2 / (TAN * (W / H)) / fw);

function setAccent(color) {
  document.documentElement.style.setProperty('--accent', color);
  floorTarget.set(color);
  if (roomGlow) roomGlow.material.color.set(color);
  if (roomPad) roomPad.material.uniforms.uColor.value.set(color);
}

/** Places n items on a gently curved grid. Returns [{x, y, z, ry}] plus the grid size. */
function curvedGrid(n, cols, cw, ch, gx, gy, radius) {
  const rows = Math.max(1, Math.ceil(n / cols));
  const out = [];
  for (let i = 0; i < n; i++) {
    const r = Math.floor(i / cols);
    const inRow = r === rows - 1 ? n - r * cols : cols;
    const c = i - r * cols;
    const flatX = (c - (inRow - 1) / 2) * (cw + gx);
    const a = flatX / radius;
    out.push({ x: radius * Math.sin(a), y: ((rows - 1) / 2 - r) * (ch + gy), z: radius * (1 - Math.cos(a)), ry: -a });
  }
  return { items: out, w: cols * cw + (cols - 1) * gx, h: rows * ch + (rows - 1) * gy };
}

// ----------------------------------------------------------------------------
// overview: department cards
// ----------------------------------------------------------------------------
function countUp(node, to) {
  if (reducedMotion || to <= 0) return;
  const t0 = performance.now(), ms = 700 + Math.min(600, to * 40);
  const step = (now) => {
    const k = Math.min(1, (now - t0) / ms);
    node.textContent = String(Math.round(to * (1 - Math.pow(1 - k, 3))));
    if (k < 1) requestAnimationFrame(step);
  };
  node.textContent = '0';
  requestAnimationFrame(step);
}

const noun = (d, n) => (d.live ? 'live screen' : d.virtual ? 'digest' : 'report') + (n === 1 ? '' : 's');

function cardElement(d, i) {
  const card = el('div', d.newCount ? 'card hot' : 'card');
  card.style.setProperty('--i', String(i));
  card.dataset.dept = d.id;
  card.style.setProperty('--c', d.color);
  card.setAttribute('role', 'button');
  card.tabIndex = 0;
  const n = d.reports.length;
  card.setAttribute('aria-label', `${d.label}: ${n} ${noun(d, n)}${d.newCount ? `, ${d.newCount} new today` : ''}. Open section.`);
  const inner = el('div', 'card-inner');
  const top = el('div', 'card-top');
  top.append(el('span', 'card-dot'), el('span', 'card-name', d.label));
  if (d.live) top.append(el('span', 'pill-live', 'LIVE'));
  if (d.newCount) top.append(el('span', 'pill-new', `${d.newCount} new`));
  const count = el('div', 'card-count');
  const big = el('b', null, String(n));
  countUp(big, n);
  count.append(big, el('span', null, noun(d, n)));
  inner.append(top, count);
  if (n) {
    const list = el('ul', 'card-latest');
    for (const r of d.reports.slice(0, 3)) {
      const li = el('li');
      const when = d.live ? (r.updated || 'Live') : fmtShort(r.date);
      li.append(el('span', null, r.title || 'Report'), el('time', null, when));
      list.append(li);
    }
    inner.append(list);
  } else {
    inner.append(el('div', 'card-empty', d.virtual ? 'No digests yet' : 'No reports yet'));
  }
  card.append(inner);
  return card;
}

let ovTitle = null;
function dropDept(d) {
  if (d.obj) overview.remove(d.obj, d.back);
  if (d.beam) { overview.remove(d.beam); d.beam.material.dispose(); }
  d.obj = d.back = d.beam = null;
}
function buildOverview() {
  if (ovTitle) overview.remove(ovTitle);
  const head = el('div', 'ov-title');
  const all = uniqueReports();
  const total = all.length;
  const fresh = all.filter((r) => r.isNew).length;
  const deptCount = depts.filter((d) => !d.virtual).length;
  const day = parseDate(feedDay);
  const h2 = el('h2');
  if (day) h2.append(el('span', null, day.toLocaleDateString('en-US', { weekday: 'long' }) + ', '), el('span', 'grad', day.toLocaleDateString('en-US', { month: 'long', day: 'numeric' })));
  else h2.append(el('span', 'grad', 'All departments'));
  head.append(
    el('div', 'eyebrow', 'BCS REPORTS HUB'),
    h2,
    el('p', null, `${total} report${total === 1 ? '' : 's'} across ${deptCount} departments${fresh ? ` · ${fresh} new today` : ''}`));
  ovTitle = new CSS3DObject(head);
  overview.add(ovTitle);
  depts.forEach(dropDept);
  depts.forEach((d, i) => {
    d.obj = new CSS3DObject(cardElement(d, i));
    const back = el('div', d.newCount ? 'card-back hot' : 'card-back');
    back.style.setProperty('--i', String(i));
    back.style.setProperty('--c', d.color);
    d.back = new CSS3DObject(back);
    overview.add(d.back, d.obj);
    if (gl) {
      d.beam = new THREE.Mesh(PLANE, beamMaterial(d.color, (i * 0.61) % 1));
      overview.add(d.beam);
    }
  });
  layoutOverview();
}

function layoutOverview() {
  const aspect = W / H, n = depts.length;
  const cols = Math.max(1, Math.min(n, aspect < 0.8 ? 2 : aspect < 1.3 ? 3 : 4));
  const grid = curvedGrid(n, cols, CARD_W, CARD_H, CARD_GX, CARD_GY, OV_RADIUS);
  depts.forEach((d, i) => {
    const p = grid.items[i];
    d.base = p;
    d.obj.position.set(p.x, p.y, p.z);
    d.obj.rotation.y = p.ry;
    d.back.position.set(p.x, p.y, p.z - 46);
    d.back.rotation.y = p.ry;
    if (d.beam) {
      const top = p.y - CARD_H / 2 + 30, h = Math.max(60, top - FLOOR_Y);
      d.beam.position.set(p.x, FLOOR_Y + h / 2, p.z - 40);
      d.beam.scale.set(CARD_W * 0.7, h, 1);
      d.beam.rotation.y = p.ry;
    }
  });
  ov.w = grid.w; ov.h = grid.h;
  if (ovTitle) ovTitle.position.set(0, grid.h / 2 + 225, 0);
  ov.home = fitDistance(grid.w, grid.h + 2 * 390, OV_RADIUS, 1.12);
  ov.enter = Math.min(ov.home * 0.6, fillDistance(CARD_W, CARD_H, 0.68, 0.86));
}

// ----------------------------------------------------------------------------
// room: wall of live report screens
// ----------------------------------------------------------------------------
function screenElement(d, report, idx) {
  const scr = el('div', 'screen');
  scr.dataset.idx = String(idx);
  scr.style.setProperty('--i', String(idx));
  scr.style.setProperty('--c', d.color);
  scr.setAttribute('role', 'button');
  scr.tabIndex = 0;
  scr.setAttribute('aria-label', `${report.title || 'Report'}, ${fmtLong(report.date)}. Open report.`);
  const inner = el('div', 'screen-inner');
  const head = el('header');
  if (report.live) head.append(el('span', 'badge live', 'LIVE'));
  else if (report.isNew) head.append(el('span', 'badge', 'NEW'));
  head.append(el('h3', null, report.title || 'Report'));
  head.append(el('span', 'meta', report.live
    ? ['Live', report.updated].filter(Boolean).join(' · ')
    : [fmtShort(report.date), report.bot].filter(Boolean).join(' · ')));
  const frame = el('div', 'frame');
  const iframe = document.createElement('iframe');
  iframe.tabIndex = -1;
  iframe.title = report.title || 'Report preview';
  iframe.setAttribute('aria-hidden', 'true');
  frame.append(el('div', 'skeleton', 'Loading report…'), iframe);
  inner.append(head, frame);
  scr.append(inner);
  return { scr, iframe };
}

async function fillScreen(rec) {
  try {
    if (rec.report.live) {
      if (!outboundCache.html) await loadOutboundBoard();
      if (!rec.alive) return;
      rec.iframe.srcdoc = prepareOutboundPanel(outboundCache.html, rec.report.key);
      rec.iframe.addEventListener('load', () => rec.scr.classList.add('ready'), { once: true });
      rec.scr.classList.remove('failed');
      return;
    }
    const html = await loadReportHtml(rec.report);
    if (!rec.alive) return;
    rec.iframe.srcdoc = prepareHtml(html, rec.report, true);
    rec.iframe.addEventListener('load', () => rec.scr.classList.add('ready'), { once: true });
  } catch (_) {
    if (!rec.alive) return;
    rec.scr.classList.add('failed');
    rec.scr.querySelector('.skeleton').textContent = rec.report.live ? 'Could not load the outbound board' : 'Could not load this report';
  }
}

function clearRoom() {
  for (const rec of rm.screens) { rec.alive = false; rec.iframe.srcdoc = ''; room.remove(rec.obj); }
  rm.screens = [];
  for (const o of [...room.children]) if (o !== roomGlow && o !== roomPad) room.remove(o);
}

function buildRoom(d) {
  clearRoom();
  rm.surround = !!d.live;
  rm.viewDist = 1;
  if (rm.surround) resetLook();
  const n = d.reports.length;
  const title = el('div', 'room-title');
  title.style.setProperty('--c', d.color);
  title.append(el('h2', null, d.label), el('p', null, n ? `${n} ${noun(d, n)}${d.newCount ? ` · ${d.newCount} new today` : ''}` : d.virtual ? 'No digests yet' : 'No reports yet'));
  const titleObj = new CSS3DObject(title);
  room.add(titleObj);
  rm.titleObj = titleObj;

  if (!n) {
    const plaque = el('div', 'plaque');
    plaque.style.setProperty('--c', d.color);
    plaque.append(el('h3', null, 'Nothing here yet'), el('p', null, d.virtual ? 'New Personal Assistant digests appear here automatically.' : 'New reports for this department appear here automatically.'));
    const po = new CSS3DObject(plaque);
    po.scale.setScalar(0.6);
    room.add(po);
    rm.plaque = po;
  } else {
    rm.plaque = null;
    d.reports.forEach((report, i) => {
      const { scr, iframe } = screenElement(d, report, i);
      const obj = new CSS3DObject(scr);
      obj.scale.setScalar(SCREEN_S);
      room.add(obj);
      rm.screens.push({ scr, iframe, obj, report, alive: true });
    });
    // load at most four at a time so a large department does not stall the page
    let next = 0;
    const pump = async () => { while (next < rm.screens.length) await fillScreen(rm.screens[next++]); };
    for (let k = 0; k < 4; k++) pump();
  }
  layoutRoom();
}

function layoutSurroundRoom() {
  const n = rm.screens.length || 1;
  const sw = SCREEN_W * SCREEN_S, sh = SCREEN_H * SCREEN_S;
  const gap = 70;
  const radius = Math.max(1200, (n * (sw + gap)) / (Math.PI * 2));
  rm.radius = radius;
  rm.screens.forEach((rec, i) => {
    const a = (i / n) * Math.PI * 2;
    rec.obj.position.set(Math.sin(a) * radius, 0, -Math.cos(a) * radius);
    rec.obj.rotation.y = a;
  });
  if (rm.titleObj) {
    rm.titleObj.position.set(0, sh / 2 + (W / H < 0.8 ? 240 : 170), -radius);
    rm.titleObj.rotation.y = 0;
  }
  rm.w = radius * 2;
  rm.h = sh;
  rm.home = 0;
  rm.cy = 0;
  rm.tall = false;
  rm.focus = 0;
  if (rm.titleObj) rm.titleObj.scale.setScalar(W / H < 0.8 ? 0.28 : 0.4);
  const fov = surroundFov();
  if (Math.abs(camera.fov - fov) > 0.01) { camera.fov = fov; camera.updateProjectionMatrix(); }
}

/** Vertical FOV that keeps the front outbound screen in frame, even on a tall phone. */
function surroundFov() {
  const sw = SCREEN_W * SCREEN_S;
  const dist = rm.radius || 1200;
  const needH = 2 * Math.atan((sw / 2) * 1.2 / dist);
  const vFromH = 2 * Math.atan(Math.tan(needH / 2) / Math.max(0.35, W / H));
  return THREE.MathUtils.clamp(Math.max(FOV, THREE.MathUtils.radToDeg(vFromH)), FOV, 75);
}

function layoutRoom() {
  if (rm.surround) { layoutSurroundRoom(); return; }
  const n = rm.screens.length, aspect = W / H;
  const sw = SCREEN_W * SCREEN_S, sh = SCREEN_H * SCREEN_S;
  const maxCols = aspect < 0.8 ? 1 : aspect < 1.3 ? 2 : n <= 4 ? 4 : n <= 6 ? 3 : 4;
  const cols = Math.max(1, Math.min(n || 1, maxCols));
  const grid = curvedGrid(n, cols, sw, sh, SCR_GX, SCR_GY, ROOM_RADIUS);
  rm.screens.forEach((rec, i) => {
    const p = grid.items[i];
    rec.obj.position.set(p.x, p.y, p.z);
    rec.obj.rotation.y = p.ry;
  });
  const wallW = n ? grid.w : 700, wallH = n ? grid.h : 300;
  const titleGap = 150, titleH = 150;
  rm.titleObj.position.set(0, wallH / 2 + titleGap + titleH / 2 - 40, 0);
  rm.titleObj.scale.setScalar(0.6);
  rm.w = wallW; rm.h = wallH;
  const head = titleGap + titleH;
  const rows = Math.max(1, Math.ceil(n / cols));
  const fitAll = fitDistance(wallW, wallH + head + 120, ROOM_RADIUS, 1.14);
  // a long wall opens on its first three rows; drag to see the rest
  const fitTop = fitDistance(wallW, Math.min(rows, 3) * (sh + SCR_GY) + head + 120, ROOM_RADIUS, 1.14);
  rm.home = Math.min(fitAll, fitTop);
  rm.tall = rows > 3;
  const top = wallH / 2 + head;
  rm.cy = rm.tall ? top + 120 - rm.home * TAN : head / 2 - 20;     // centre of what the home view shows
  rm.focus = Math.min(rm.home * 0.7, fillDistance(sw, sh, 0.8, 0.92));
}

const roomHome = () => new THREE.Vector3(0, rm.cy, ROOM_Z + rm.home);

// ----------------------------------------------------------------------------
// camera moves
// ----------------------------------------------------------------------------
const easeIn = (k) => k * k;
const easeOut = (k) => 1 - Math.pow(1 - k, 3);
const easeInOut = (k) => (k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2);
function tween(ms, fn, ease = easeInOut) {
  if (reducedMotion) ms = 1;
  return new Promise((resolve) => {
    const t0 = performance.now();
    const step = (now) => {
      const k = Math.min(1, (now - t0) / ms);
      fn(ease(k));
      if (k < 1) requestAnimationFrame(step); else resolve();
    };
    requestAnimationFrame(step);
  });
}

function clampGoal() {
  const g = cam.goal;
  if (mode === 'overview') {
    g.x = THREE.MathUtils.clamp(g.x, -ov.w / 2, ov.w / 2);
    g.y = THREE.MathUtils.clamp(g.y, -ov.h / 2, ov.h / 2);
    if (g.z >= ov.home) { g.x *= 0.5; g.y *= 0.5; }
  } else if (rm.surround) {
    g.x = 0;
    g.y = rm.cy;
    g.z = ROOM_Z;
  } else {
    g.x = THREE.MathUtils.clamp(g.x, -rm.w / 2, rm.w / 2);
    g.y = THREE.MathUtils.clamp(g.y, -rm.h / 2, Math.max(rm.cy, rm.h / 2 + 200));
    if (g.z - ROOM_Z >= rm.home) { g.x *= 0.5; if (!rm.tall) g.y += (rm.cy - g.y) * 0.5; }
  }
}

const raycaster = new THREE.Raycaster();
const ndc = new THREE.Vector2();
function rayDir(cx, cy) {
  ndc.set((cx / W) * 2 - 1, -(cy / H) * 2 + 1);
  raycaster.setFromCamera(ndc, camera);
  return raycaster.ray.direction;
}
const hitAt = (cx, cy, sel) => { const t = document.elementFromPoint(cx, cy); return t && t.closest ? t.closest(sel) : null; };

function zoomAt(cx, cy, factor) {
  if (busy || mode === 'focus') return;
  const dist = cam.goal.z - planeZ();
  let nd = dist * factor;
  if (mode === 'overview') {
    if (factor < 1 && nd < ov.enter) {
      const card = hitAt(cx, cy, '.card');
      const d = card && depts.find((x) => x.id === card.dataset.dept);
      if (d) { enterRoom(d); return; }
      nd = Math.max(nd, ov.enter);
      if (nd >= dist) return;
    }
    nd = Math.min(nd, ov.home * 1.1);
  } else if (rm.surround) {
    rm.viewDist *= factor;
    if (factor > 1 && rm.viewDist > 1.32) { rm.viewDist = 1; leaveRoom(); return; }
    if (factor < 1) {
      const scr = hitAt(cx, cy, '.screen');
      if (scr) { rm.viewDist = 1; openFocus(Number(scr.dataset.idx)); return; }
      rm.viewDist = Math.max(rm.viewDist, 0.85);
    }
    rm.viewDist = THREE.MathUtils.clamp(rm.viewDist, 0.85, 1.35);
    updateHint();
    return;
  } else {
    if (factor > 1 && nd > rm.home * 1.32) { leaveRoom(); return; }
    if (factor < 1 && nd < rm.focus) {
      const scr = hitAt(cx, cy, '.screen');
      if (scr) { openFocus(Number(scr.dataset.idx)); return; }
      nd = Math.max(nd, rm.focus);
      if (nd >= dist) return;
    }
  }
  const dir = rayDir(cx, cy);
  cam.goal.addScaledVector(dir, (dist - nd) / -dir.z);
  cam.goal.z = planeZ() + nd;
  clampGoal();
  updateHint();
}

function panBy(dx, dy) {
  if (busy || mode === 'focus') return;
  if (isSurround()) {
    const sens = 0.0048;
    look.gy += dx * sens;
    look.gp = THREE.MathUtils.clamp(look.gp + dy * sens * 0.75, -MAX_PITCH, MAX_PITCH);
    // keep yaw in a small range so the values don't grow without bound
    if (look.gy > Math.PI) { look.gy -= Math.PI * 2; look.yaw -= Math.PI * 2; }
    if (look.gy < -Math.PI) { look.gy += Math.PI * 2; look.yaw += Math.PI * 2; }
    updateHint();
    return;
  }
  const wpp = (2 * (cam.goal.z - planeZ()) * TAN) / H;
  cam.goal.x -= dx * wpp;
  cam.goal.y += dy * wpp;
  clampGoal();
}

function streaks(dir) {
  const w = document.getElementById('warp');
  if (!w || reducedMotion) return;
  w.classList.remove('in', 'out');
  void w.offsetWidth;            // restart the animation
  w.classList.add(dir);
}

async function enterRoom(d, instant = false) {
  if (busy || mode !== 'overview') return;
  busy = true;
  current = d;
  setAccent(d.color);
  if (!instant) {
    const from = cam.pos.clone();
    const to = new THREE.Vector3(d.base.x, d.base.y, d.base.z + 330);
    warpDir = 1; warpTarget = 1; streaks('in');
    await tween(430, (k) => { cam.pos.lerpVectors(from, to, k); els.fade.style.opacity = String(k * k); }, easeIn);
  }
  overview.visible = false;
  room.visible = true;
  buildRoom(d);
  mode = 'room';
  const home = roomHome();
  const start = home.clone();
  start.z = ROOM_Z + (rm.surround ? Math.max(400, (rm.radius || 1200) * 0.28) : rm.home * 1.9);
  els.fade.style.opacity = '1';
  updateHud();
  warpTarget = 0;
  await tween(instant ? 1 : 700, (k) => { cam.pos.lerpVectors(start, home, k); els.fade.style.opacity = String(1 - k); }, easeOut);
  cam.goal.copy(home);
  els.fade.style.opacity = '0';
  busy = false;
  updateHint();
  try { history.replaceState(null, '', '#' + d.id); } catch (_) {}
}

async function leaveRoom() {
  if (busy || mode !== 'room') return;
  busy = true;
  const from = cam.pos.clone();
  const out = from.clone(); out.z += rm.home * 0.9;
  warpDir = -1; warpTarget = 1; streaks('out');
  await tween(330, (k) => { cam.pos.lerpVectors(from, out, k); els.fade.style.opacity = String(k); }, easeIn);
  const d = current;
  clearRoom();
  rm.surround = false;
  resetLook();
  if (Math.abs(camera.fov - FOV) > 0.01) { camera.fov = FOV; camera.updateProjectionMatrix(); }
  room.visible = false;
  overview.visible = true;
  mode = 'overview';
  current = null;
  setAccent('#9a4dff');
  updateHud();
  const start = new THREE.Vector3(d.base.x, d.base.y, d.base.z + ov.enter * 0.8);
  const home = new THREE.Vector3(0, 0, ov.home);
  warpTarget = 0;
  await tween(750, (k) => { cam.pos.lerpVectors(start, home, k); els.fade.style.opacity = String(1 - Math.min(1, k * 2.2)); }, easeOut);
  cam.goal.copy(home);
  els.fade.style.opacity = '0';
  busy = false;
  try { history.replaceState(null, '', location.pathname + location.search); } catch (_) {}
}

// ----------------------------------------------------------------------------
// focus: one report, full size
// ----------------------------------------------------------------------------
async function showFocusReport(idx) {
  const d = current, report = d.reports[idx];
  focusIdx = idx;
  els.focusTitle.querySelector('b').textContent = report.title || 'Report';
  els.focusTitle.querySelector('span').textContent = report.live
    ? [d.label, 'Live', report.updated].filter(Boolean).join(' · ')
    : [d.label, fmtLong(report.date), report.bot].filter(Boolean).join(' · ');
  els.focusPos.textContent = `${idx + 1} of ${d.reports.length}`;
  els.focusPrev.disabled = idx <= 0;
  els.focusNext.disabled = idx >= d.reports.length - 1;
  els.focusOpen.href = report.live ? report.href : new URL(report.href, HUB_BASE).href;
  els.focusOpen.textContent = report.live ? 'Open live board' : 'Open in new tab';
  els.focusFrame.removeAttribute('src');
  els.focusFrame.srcdoc = '<body style="margin:0;background:#0f1622"></body>';
  try {
    if (report.live) {
      if (!outboundCache.html) await loadOutboundBoard();
      if (mode !== 'focus' || focusIdx !== idx) return;
      els.focusFrame.srcdoc = prepareOutboundPanel(outboundCache.html, report.key);
      return;
    }
    const html = await loadReportHtml(report);
    if (mode !== 'focus' || focusIdx !== idx) return;
    els.focusFrame.srcdoc = prepareHtml(html, report, false);
  } catch (_) {
    if (mode !== 'focus' || focusIdx !== idx) return;
    els.focusFrame.srcdoc = `<body style="margin:0;display:grid;place-items:center;height:100vh;font:16px system-ui;background:#0f1622;color:#e39a8a">${report.live ? 'Could not load the outbound board.' : 'Could not load this report.'}</body>`;
  }
}

function openFocus(idx) {
  if (busy || mode !== 'room' || !current || !current.reports[idx]) return;
  const rec = rm.screens[idx];
  const rect = rec ? rec.scr.getBoundingClientRect() : { left: W / 2, top: H / 2, width: 0, height: 0 };
  mode = 'focus';
  els.focus.hidden = false;
  showFocusReport(idx);
  if (!reducedMotion && els.focus.animate) {
    els.focus.animate([
      { transform: `translate(${rect.left}px, ${rect.top}px) scale(${rect.width / W}, ${rect.height / H})`, opacity: 0.3 },
      { transform: 'none', opacity: 1 },
    ], { duration: 320, easing: 'cubic-bezier(0.2, 0.8, 0.2, 1)' });
  }
  updateHud();
  els.focusBack.focus({ preventScroll: true });
}

function closeFocus() {
  if (mode !== 'focus') return;
  const rec = rm.screens[focusIdx];
  mode = 'room';
  const done = () => { els.focus.hidden = true; els.focusFrame.removeAttribute('src'); els.focusFrame.srcdoc = ''; };
  if (!reducedMotion && els.focus.animate && rec) {
    const rect = rec.scr.getBoundingClientRect();
    const a = els.focus.animate([
      { transform: 'none', opacity: 1 },
      { transform: `translate(${rect.left}px, ${rect.top}px) scale(${rect.width / W}, ${rect.height / H})`, opacity: 0 },
    ], { duration: 240, easing: 'cubic-bezier(0.4, 0, 0.8, 0.4)' });
    a.onfinish = done; a.oncancel = done;
  } else done();
  focusIdx = -1;
  updateHud();
}

// Inside the focused report: Esc, pinch-out and Ctrl+scroll-out all step back to the wall.
els.focusFrame.addEventListener('load', () => {
  let doc;
  try { doc = els.focusFrame.contentDocument; } catch (_) { return; }
  if (!doc) return;
  doc.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeFocus(); });
  let acc = 0;
  doc.addEventListener('wheel', (e) => {
    if (!e.ctrlKey) return;
    e.preventDefault();
    acc = e.deltaY > 0 ? acc + e.deltaY : 0;
    if (acc > 40) { acc = 0; closeFocus(); }
  }, { passive: false });
  let pinch0 = 0;
  const span = (t) => Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY);
  doc.addEventListener('touchstart', (e) => { if (e.touches.length === 2) pinch0 = span(e.touches); }, { passive: true });
  doc.addEventListener('touchmove', (e) => {
    if (e.touches.length === 2 && pinch0 && span(e.touches) < pinch0 * 0.6) { pinch0 = 0; closeFocus(); }
  }, { passive: true });
});

// ----------------------------------------------------------------------------
// HUD
// ----------------------------------------------------------------------------
let toastTimer = 0;
function toast(msg) {
  els.toast.textContent = msg;
  els.toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { els.toast.hidden = true; }, 4200);
}
function updateHint() {
  let text;
  if (mode === 'overview') text = coarse ? 'Pinch to zoom · Drag to move · Zoom into a department to open it' : 'Scroll or pinch to zoom · Drag to move · Zoom into a department to open it';
  else if (mode === 'room') {
    if (rm.surround) {
      text = rm.viewDist > 1.04
        ? 'Keep zooming out to return to all departments'
        : 'Drag or use arrow keys to look around · Click a screen to open it · Zoom out or Esc to go back';
    } else {
      text = cam.goal.z - ROOM_Z > rm.home * 1.04
        ? 'Keep zooming out to return to all departments'
        : !rm.screens.length ? 'Zoom out to go back to all departments'
        : `Zoom into a report to open it · Drag to ${rm.tall ? 'see more' : 'move'} · Zoom out to go back`;
    }
  }
  els.hint.hidden = mode === 'focus' || !text;
  if (text) els.hint.textContent = text;
}
function updateHud() {
  const inRoom = mode !== 'overview' && current;
  els.crumbDept.hidden = els.sepDept.hidden = !inRoom;
  if (inRoom) els.crumbDept.textContent = current.label;
  document.title = inRoom ? `${current.label} · BCS Reports Dashboard` : 'BCS Reports Dashboard';
  updateHint();
}
function updateStatus(manifest) {
  const total = uniqueReports().length;
  const stamp = fmtStamp(manifest.generatedAt);
  els.status.textContent = `${total} report${total === 1 ? '' : 's'}${stamp ? ` · feed updated ${stamp}` : ''}`;
}

els.crumbHome.addEventListener('click', () => { if (mode === 'focus') closeFocus(); if (mode === 'room') leaveRoom(); else if (!busy) { cam.goal.set(0, 0, ov.home); } });
els.crumbDept.addEventListener('click', () => { if (mode === 'focus') closeFocus(); else if (mode === 'room' && !busy) { if (rm.surround) { resetLook(); rm.viewDist = 1; } cam.goal.copy(roomHome()); } });
els.focusBack.addEventListener('click', closeFocus);
els.focusPrev.addEventListener('click', () => { if (focusIdx > 0) showFocusReport(focusIdx - 1); });
els.focusNext.addEventListener('click', () => { if (current && focusIdx < current.reports.length - 1) showFocusReport(focusIdx + 1); });
els.btnRefresh.addEventListener('click', () => refresh(true));
els.btnLock.addEventListener('click', () => {
  try { localStorage.removeItem(LS_PASS); localStorage.removeItem(LS_EXP); } catch (_) {}
  location.reload();
});

// ----------------------------------------------------------------------------
// input: wheel / pinch zoom, drag pan, tap to open, keyboard
// ----------------------------------------------------------------------------
const pointers = new Map();
let downTarget = null, moved = 0, pinchSpan = 0, pinchMid = null;
const mouse = { x: 0, y: 0, active: false };

function activate(target) {
  if (!target) return;
  if (target.classList.contains('card')) {
    const d = depts.find((x) => x.id === target.dataset.dept);
    if (d) enterRoom(d);
  } else if (target.classList.contains('screen')) {
    openFocus(Number(target.dataset.idx));
  }
}

els.stage.addEventListener('pointerdown', (e) => {
  if (mode === 'focus') return;
  if (e.pointerType === 'mouse' && e.button !== 0) return;
  pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
  try { els.stage.setPointerCapture(e.pointerId); } catch (_) {}
  if (pointers.size === 1) {
    downTarget = e.target.closest ? e.target.closest('.card, .screen') : null;
    moved = 0;
  } else if (pointers.size === 2) {
    const [a, b] = [...pointers.values()];
    pinchSpan = Math.hypot(a.x - b.x, a.y - b.y);
    pinchMid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    downTarget = null;
  }
});
els.stage.addEventListener('pointermove', (e) => {
  if (e.pointerType === 'mouse' && !coarse) { mouse.x = (e.clientX / W) * 2 - 1; mouse.y = (e.clientY / H) * 2 - 1; mouse.active = true; }
  else if (e.pointerType !== 'mouse') mouse.active = false;
  const p = pointers.get(e.pointerId);
  if (!p) return;
  const dx = e.clientX - p.x, dy = e.clientY - p.y;
  p.x = e.clientX; p.y = e.clientY;
  if (pointers.size === 1) {
    moved += Math.abs(dx) + Math.abs(dy);
    if (moved > 6) { els.stage.classList.add('dragging'); panBy(dx, dy); }
  } else if (pointers.size === 2) {
    const [a, b] = [...pointers.values()];
    const span = Math.hypot(a.x - b.x, a.y - b.y);
    const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    if (pinchSpan > 0 && span > 0) zoomAt(mid.x, mid.y, pinchSpan / span);
    if (pinchMid) panBy(mid.x - pinchMid.x, mid.y - pinchMid.y);
    pinchSpan = span; pinchMid = mid;
  }
});
function pointerEnd(e) {
  if (!pointers.has(e.pointerId)) return;
  const wasSingle = pointers.size === 1;
  pointers.delete(e.pointerId);
  els.stage.classList.remove('dragging');
  if (e.type === 'pointerup' && wasSingle && moved <= 6 && downTarget) activate(downTarget);
  if (pointers.size < 2) { pinchSpan = 0; pinchMid = null; }
  if (pointers.size === 0) downTarget = null;
}
els.stage.addEventListener('pointerup', pointerEnd);
els.stage.addEventListener('pointercancel', pointerEnd);
els.stage.addEventListener('pointerleave', (e) => { if (e.pointerType === 'mouse') mouse.active = false; });

window.addEventListener('wheel', (e) => {
  if (mode === 'focus' || !els.gate.hidden) return;
  e.preventDefault();
  let dy = e.deltaY;
  if (e.deltaMode === 1) dy *= 32; else if (e.deltaMode === 2) dy *= H;
  dy = THREE.MathUtils.clamp(dy, -240, 240);
  // trackpad pinch arrives as ctrl+wheel with small deltas
  zoomAt(e.clientX, e.clientY, Math.exp(dy * (e.ctrlKey ? 0.012 : 0.0032)));
}, { passive: false });
for (const t of ['gesturestart', 'gesturechange', 'gestureend']) window.addEventListener(t, (e) => e.preventDefault());

window.addEventListener('keydown', (e) => {
  if (!els.gate.hidden) return;
  const k = e.key;
  if (k === 'Escape') {
    if (mode === 'focus') closeFocus(); else if (mode === 'room') leaveRoom();
    return;
  }
  if (mode === 'focus') {
    if (k === 'ArrowLeft') els.focusPrev.click();
    if (k === 'ArrowRight') els.focusNext.click();
    return;
  }
  const t = e.target;
  if ((k === 'Enter' || k === ' ') && t && t.classList && (t.classList.contains('card') || t.classList.contains('screen'))) {
    e.preventDefault();
    activate(t);
    return;
  }
  const step = 90;
  if (k === '+' || k === '=') zoomAt(W / 2, H / 2, 0.8);
  else if (k === '-' || k === '_') zoomAt(W / 2, H / 2, 1.25);
  else if (k === 'ArrowLeft') panBy(step, 0);
  else if (k === 'ArrowRight') panBy(-step, 0);
  else if (k === 'ArrowUp') panBy(0, step);
  else if (k === 'ArrowDown') panBy(0, -step);
});

function resize() {
  const w = els.stage.clientWidth || innerWidth, h = els.stage.clientHeight || innerHeight;
  if (w === W && h === H && sized) return;
  sized = true;
  W = w; H = h;
  camera.aspect = W / H;
  camera.updateProjectionMatrix();
  if (gl) gl.setSize(W, H);
  css.setSize(W, H);
  if (depts.length) layoutOverview();
  if (mode !== 'overview' && current) layoutRoom();
  if (!busy) {
    if (mode === 'overview') cam.goal.z = Math.min(cam.goal.z, ov.home * 1.1);
    clampGoal();
  }
}
let sized = false;
window.addEventListener('resize', resize);
if (window.ResizeObserver) new ResizeObserver(resize).observe(els.stage);

// ----------------------------------------------------------------------------
// render loop
// ----------------------------------------------------------------------------
let last = performance.now();
const rot = { x: 0, y: 0 };
function frame(now) {
  const dt = Math.min(0.05, (now - last) / 1000);
  last = now;
  if (!busy) cam.pos.lerp(cam.goal, 1 - Math.exp(-dt * 12));
  camera.position.copy(cam.pos);
  if (rm.surround && mode !== 'overview') {
    const k = 1 - Math.exp(-dt * 12);
    look.yaw += (look.gy - look.yaw) * k;
    look.pitch += (look.gp - look.pitch) * k;
    camera.rotation.order = 'YXZ';
    camera.rotation.set(look.pitch, look.yaw, 0);
  } else {
    // slight parallax from the mouse so the scene reads as 3D
    const want = mouse.active && !reducedMotion && pointers.size === 0 ? mouse : { x: 0, y: 0 };
    rot.y += (-want.x * 0.035 - rot.y) * Math.min(1, dt * 5);
    rot.x += (-want.y * 0.022 - rot.x) * Math.min(1, dt * 5);
    camera.rotation.order = 'XYZ';
    camera.rotation.set(rot.x, rot.y, 0);
  }

  if (mode === 'overview' && !reducedMotion) {
    depts.forEach((d, i) => {
      if (!d.obj) return;
      const bob = Math.sin(now * 0.0007 + i * 1.3) * 7;
      d.obj.position.y = d.base.y + bob;
      d.back.position.y = d.base.y + bob;
    });
  }
  if (gl && mode !== 'focus') {
    floorColor.lerp(floorTarget, Math.min(1, dt * 3));
    floorMat.uniforms.uCam.value.copy(cam.pos);
    floorMat.uniforms.uCenterZ.value = mode === 'overview' ? 0 : ROOM_Z;
    if (!reducedMotion) {
      uTime.value = now / 1000;
      warp += (warpTarget - warp) * Math.min(1, dt * 7);
      if (warp < 0.002 && warpTarget === 0) warp = 0;
      // stars drift gently toward the viewer, and rush past while flying between levels
      flow.z = (flow.z + dt * (70 + warp * 15000) * (warp > 0.01 ? warpDir : 1) + STAR_BOX.z) % STAR_BOX.z;
      flow.x = (flow.x + dt * 22) % STAR_BOX.x;
      flow.y = (flow.y + dt * 6) % STAR_BOX.y;
      const fov = ((rm.surround && mode !== 'overview') ? surroundFov() : FOV) + warp * 9;
      if (Math.abs(camera.fov - fov) > 0.01) { camera.fov = fov; camera.updateProjectionMatrix(); }
      for (const s of nebulae) {
        const { x, y, i } = s.userData, t = uTime.value;
        s.position.x = x + Math.sin(t * 0.045 + i * 2.1) * 2600;
        s.position.y = y + Math.cos(t * 0.037 + i * 1.3) * 1100;
        s.material.opacity = 0.15 + 0.06 * Math.sin(t * 0.33 + i * 2.4);
      }
    }
    starMat.uniforms.uCam.value.copy(cam.pos);
    starMat.uniforms.uScale.value = H * gl.getPixelRatio();
    starMat.uniforms.uWarp.value = warp;
    gl.render(scene, camera);
  }
  if (mode !== 'focus' || els.focus.getAnimations?.().length) css.render(scene, camera);
  requestAnimationFrame(frame);
}

// ----------------------------------------------------------------------------
// feed lifecycle
// ----------------------------------------------------------------------------
function applyManifest(manifest, announce) {
  const stamp = JSON.stringify(manifest.lands || []);
  const changed = stamp !== manifestStamp;
  if (changed) {
    const before = uniqueReports().length;
    const oldCurrentHrefs = current ? current.reports.map((r) => r.href).join('|') : '';
    const currentId = current ? current.id : null;
    depts.forEach(dropDept);
    depts = buildDepts(manifest);
    manifestStamp = stamp;
    feedDay = manifest.today || '';
    buildOverview();
    if (currentId) {
      const next = depts.find((d) => d.id === currentId);
      if (!next) { location.reload(); return; }
      current = next;
      if (mode === 'room' && next.reports.map((r) => r.href).join('|') !== oldCurrentHrefs) buildRoom(next);
    }
    const after = uniqueReports().length;
    if (announce && before) toast(after > before ? `${after - before} new report${after - before === 1 ? '' : 's'} arrived` : 'Reports updated');
  } else if (announce === 'manual') {
    toast('Already up to date');
  }
  updateStatus(manifest);
}

let refreshing = false;
async function refresh(manual = false) {
  if (refreshing || !hashed) return;
  refreshing = true;
  try {
    applyManifest(await loadManifest(), manual ? 'manual' : true);
    await refreshOutbound(manual);
  } catch (err) {
    if (err.message === 'locked') { location.reload(); return; }
    if (manual) toast('Could not reach the reports feed');
  } finally { refreshing = false; }
}

async function refreshOutbound(manual = false) {
  try {
    const prev = outboundCache.updated;
    await loadOutboundBoard();
    if (current && current.live) {
      if (mode === 'room') {
        for (const rec of rm.screens) {
          if (!rec.alive || !rec.report.live) continue;
          rec.scr.classList.remove('ready');
          rec.iframe.srcdoc = prepareOutboundPanel(outboundCache.html, rec.report.key);
          rec.iframe.addEventListener('load', () => rec.scr.classList.add('ready'), { once: true });
          const meta = rec.scr.querySelector('.meta');
          if (meta) meta.textContent = ['Live', rec.report.updated].filter(Boolean).join(' · ');
        }
      }
      if (mode === 'focus' && current.reports[focusIdx]) await showFocusReport(focusIdx);
    }
    if (manual && mode !== 'focus') {
      const d = depts.find((x) => x.live);
      if (d && d.obj) {
        // refresh the card's "updated" stamps in place
        d.obj.element.querySelectorAll('.card-latest time').forEach((t, i) => {
          const r = d.reports[i];
          if (r) t.textContent = r.updated || 'Live';
        });
      }
    }
    if (manual && outboundCache.updated && outboundCache.updated !== prev) toast('Outbound board updated');
  } catch (_) {
    if (manual) toast('Could not reach the outbound board');
  }
}

function shootingStar() {
  const sky = document.getElementById('sky');
  if (sky && !document.hidden && mode !== 'focus') {
    const s = el('div', 'shoot');
    const fromLeft = Math.random() < 0.5;
    s.style.left = `${(fromLeft ? 5 : 45) + Math.random() * 45}%`;
    s.style.top = `${4 + Math.random() * 38}%`;
    s.style.setProperty('--r', `${fromLeft ? 14 + Math.random() * 22 : 166 - Math.random() * 22}deg`);
    s.style.setProperty('--dist', `${Math.round(W * (0.3 + Math.random() * 0.35))}px`);
    s.style.setProperty('--t', `${(0.8 + Math.random() * 0.7).toFixed(2)}s`);
    s.addEventListener('animationend', () => s.remove());
    sky.append(s);
  }
  setTimeout(shootingStar, 3500 + Math.random() * 8000);
}

function start(manifest) {
  els.loading.hidden = true;
  els.gate.hidden = true;
  els.hud.hidden = false;
  resize();
  applyManifest(manifest, false);
  cam.pos.set(0, 0, ov.home * 1.5);
  cam.goal.set(0, 0, ov.home);
  updateHud();
  requestAnimationFrame((t) => { last = t; frame(t); });
  const wanted = decodeURIComponent(location.hash.slice(1));
  const d = depts.find((x) => x.id === wanted);
  if (d) enterRoom(d, true);
  loadOutboundBoard().then(() => {
    const ob = depts.find((x) => x.live);
    if (!ob || !ob.obj || !outboundCache.updated) return;
    ob.obj.element.querySelectorAll('.card-latest time').forEach((t, i) => {
      const r = ob.reports[i];
      if (r) t.textContent = r.updated || 'Live';
    });
  }).catch(() => {});
  if (!reducedMotion) setTimeout(shootingStar, 2500);
  setInterval(() => { if (!document.hidden) refresh(false); }, REFRESH_MS);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(false); });
}

function showGate(message) {
  els.loading.hidden = true;
  els.gate.hidden = false;
  if (message) els.gateErr.textContent = message;
  els.gatePass.focus();
}
els.gateForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = els.gatePass.value;
  if (!pw) return;
  els.gateSubmit.disabled = true;
  els.gateSubmit.textContent = 'Unlocking…';
  els.gateErr.textContent = '';
  try {
    if (!hubCipher) hubCipher = extractCipher(await fetchText(HUB_BASE + 'index.html'));
    const h = await hashPassword(pw, hubCipher.salt);
    const html = await decode(hubCipher.msg, h);
    if (html == null) {
      els.gateErr.textContent = "That password didn't work. Try again.";
      els.gatePass.select();
    } else {
      hashed = h;
      if (els.gateRemember.checked) remember(h);
      els.gatePass.value = '';
      start(parseManifest(html));
    }
  } catch (_) {
    els.gateErr.textContent = 'Could not reach the reports feed. Check your connection and try again.';
  } finally {
    els.gateSubmit.disabled = false;
    els.gateSubmit.textContent = 'Unlock';
  }
});

(async function boot() {
  hashed = readRemembered();
  try {
    start(await loadManifest());
  } catch (err) {
    if (err.message === 'locked') showGate('');
    else showGate('Could not reach the reports feed. Check your connection and try again.');
  }
})();
