// Enigma Codes — in-browser demo. The seal runs the REAL enigmar engine.
//
// Pyodide (CPython compiled to WebAssembly) loads the enigmar package straight
// from the repo and runs docs/seal.py. The format-preserving step is an actual
// Enigma — rotors, reflector, plugboard — derived from the passphrase and the
// per-code nonce; an HMAC-SHA256 tag does the sealing. Everything is client-side.
//
// This is a MECHANISM demo, not a secured service: the key lives in the browser
// here, so anyone could read it. In production the key stays server-side.

const PYODIDE_VERSION = "v0.26.4";
const PYODIDE_URL = `https://cdn.jsdelivr.net/pyodide/${PYODIDE_VERSION}/full/`;
const ENIGMAR_RAW = "https://raw.githubusercontent.com/hjack-rw/EnigmaR/main/enigmar/";
const ENIGMAR_FILES = ["__init__.py", "machine.py", "cipher.py", "fpe.py"];

const $ = id => document.getElementById(id);
let seal = null, lastCode = "";

function setStatus(msg, state) {          // state: "busy" | "ready" | "error" | ""
  $("statusText").textContent = msg;     // leave the rotor discs in place
  $("status").className = "status" + (state ? " " + state : "");
}
function enableControls(on) {
  ["mint", "checkBtn", "tamperBtn"].forEach(id => { $(id).disabled = !on; });
}

async function boot() {
  enableControls(false);
  try {
    setStatus("Loading Python (Pyodide, first load only)…", "busy");
    const py = await loadPyodide({ indexURL: PYODIDE_URL });

    setStatus("Fetching the Enigma engine from the repo…", "busy");
    const sources = await Promise.all(
      ENIGMAR_FILES.map(f => fetch(ENIGMAR_RAW + f).then(r => {
        if (!r.ok) throw new Error(`could not fetch enigmar/${f} (${r.status})`);
        return r.text();
      }))
    );
    py.FS.mkdirTree("/lib/enigmar");
    ENIGMAR_FILES.forEach((f, i) => py.FS.writeFile(`/lib/enigmar/${f}`, sources[i]));

    const sealSrc = await fetch("seal.py").then(r => {
      if (!r.ok) throw new Error(`could not fetch seal.py (${r.status})`);
      return r.text();
    });
    py.FS.writeFile("/lib/seal.py", sealSrc);

    py.runPython("import sys; sys.path.insert(0, '/lib')");
    seal = py.pyimport("seal");                     // runs the real rotor engine

    setStatus("Engine ready. The codes below are minted by the real Enigma.", "ready");
    enableControls(true);
  } catch (e) {
    setStatus("Couldn't load the engine: " + e.message + " (needs a network connection).", "error");
  }
}

function mint() {
  try {
    const key = $("key").value || "demo-master-key";
    const clamp = (v, hi) => Math.max(0, Math.min(hi, parseInt(v, 10) || 0));
    const cid = clamp($("creator").value, 32767);   // 3 base32 symbols
    const disc = clamp($("discount").value, 31);     // 1 base32 symbol
    const exp = clamp($("expiry").value, 32767);     // 3 base32 symbols
    const ser = Math.floor(Math.random() * 32768);   // per-code nonce
    lastCode = seal.mint(key, cid, disc, exp, ser);
    $("code").textContent = lastCode;
    $("check").value = lastCode;
    $("verdict").className = "verdict muted";
    $("verdict").textContent = "Minted. Now Check it, or Tamper it.";
  } catch (e) {
    setStatus("Mint failed: " + e.message, "error");
  }
}

function decode(key, code) {
  const r = seal.check(key, code);
  if (r === null || r === undefined) return null;
  const obj = r.toJs({ dict_converter: Object.fromEntries });
  r.destroy();
  return obj;
}

function validateInput() {
  const v = $("verdict");
  try {
    const key = $("key").value || "demo-master-key";
    const f = decode(key, $("check").value);
    if (f) {
      v.className = "verdict ok";
      v.textContent = `✓ genuine: id ${f.id}, ${f.discount}% off, serial ${f.serial}`;
    } else {
      v.className = "verdict bad";
      v.textContent = "✗ rejected: forged, tampered, or wrong key";
    }
  } catch (e) {
    v.className = "verdict bad";
    v.textContent = "Check failed: " + e.message;
  }
}

function tamper() {
  if (!lastCode) return;
  const ALPH = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const chars = [...lastCode];
  let i = Math.floor(Math.random() * chars.length);
  while (chars[i] === "-") i = (i + 1) % chars.length;
  chars[i] = ALPH[(ALPH.indexOf(chars[i]) + 1) % ALPH.length];
  $("check").value = chars.join("");
  validateInput();
}

document.addEventListener("DOMContentLoaded", () => {
  $("mint").addEventListener("click", mint);
  $("checkBtn").addEventListener("click", validateInput);
  $("tamperBtn").addEventListener("click", tamper);
  boot();
});
