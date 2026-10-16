// @ts-check
import { byId } from "./dom.js";
import { b64urlDecode, decrypt, parseKey } from "./vault-crypto.js";

const status = byId("status", HTMLElement);
const reveal = byId("reveal", HTMLButtonElement);
const secret = byId("secret", HTMLElement);

const id = location.pathname.split("/").pop() ?? "";

let finished = false; // the server answered: the secret is gone, whatever the page shows now

/** The key must not stay in the address bar, history or a bookmark once the secret is gone. */
function clearFragment() {
  finished = true;
  history.replaceState(null, "", location.pathname);
}

/** @param {import("./vault-crypto.js").Bytes} key */
async function open(key) {
  reveal.disabled = true;
  let res;
  try {
    res = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
      method: "POST",
      referrerPolicy: "no-referrer",
    });
  } catch {
    status.textContent = "Could not reach the server. The secret was not opened; try again.";
    reveal.disabled = false;
    return;
  }
  if (res.status === 404) {
    clearFragment();
    reveal.hidden = true;
    status.textContent = "This secret does not exist, was already read or has expired.";
    return;
  }
  if (!res.ok) {
    status.textContent = `Unexpected server error (HTTP ${res.status}). Try again.`;
    reveal.disabled = false;
    return;
  }
  const body = await res.json();
  clearFragment();
  reveal.hidden = true;
  try {
    secret.textContent = await decrypt(key, b64urlDecode(body.iv), b64urlDecode(body.ciphertext));
    secret.hidden = false;
    status.textContent = "Secret opened. It is now deleted from the server.";
  } catch {
    status.textContent =
      "Could not decrypt. The link is damaged or the secret was altered. It is deleted from the server.";
  }
}

/** Shows what the current address allows: reveal with a whole key, else "incomplete link". */
function render() {
  if (finished) return;
  const key = parseKey(location.hash.slice(1));
  if (!key) {
    // No whole key: nothing to decrypt with, so do not call the server (that would burn the secret).
    reveal.hidden = true;
    status.textContent =
      "Incomplete link. Ask the sender for the full link, including the part after #.";
    return;
  }
  status.textContent = "Ready. Opening the secret deletes it from the server.";
  reveal.hidden = false;
  reveal.onclick = () => open(key);
}

render();
// Pasting the missing part into the address bar changes only the fragment: no page reload.
addEventListener("hashchange", render);
