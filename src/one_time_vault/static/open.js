// @ts-check
import { byId } from "./dom.js";
import { b64urlDecode, b64urlEncode, decrypt, parseKey, passwordVerifier } from "./vault-crypto.js";

const status = byId("status", HTMLElement);
const reveal = byId("reveal", HTMLButtonElement);
const secret = byId("secret", HTMLElement);
const form = byId("password-form", HTMLFormElement);
const password = byId("access-password", HTMLInputElement);
const submit = byId("open-secret", HTMLButtonElement);

const id = location.pathname.split("/").pop() ?? "";

/** PBKDF2 cost the server asked for; kept for the next try after a wrong password. */
let iterations = 0;
let finished = false; // the server answered: the secret is gone, whatever the page shows now

/** The key must not stay in the address bar, history or a bookmark once the secret is gone. */
function clearFragment() {
  finished = true;
  history.replaceState(null, "", location.pathname);
}

/**
 * Ask the server for the secret. Without a verifier it only answers "password required" for a
 * protected secret, which costs no attempt.
 * @param {import("./vault-crypto.js").Bytes} key
 * @param {import("./vault-crypto.js").Bytes | null} verifier
 */
async function revealSecret(key, verifier) {
  reveal.disabled = true;
  submit.disabled = true;
  let res;
  try {
    res = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
      method: "POST",
      referrerPolicy: "no-referrer",
      ...(verifier && {
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ verifier: b64urlEncode(verifier) }),
      }),
    });
  } catch {
    status.textContent = "Could not reach the server. The secret was not opened; try again.";
    reveal.disabled = false;
    submit.disabled = false;
    return;
  }
  if (res.status === 404) {
    clearFragment();
    reveal.hidden = true;
    form.hidden = true;
    status.textContent = "This secret does not exist, was already read or has expired.";
    return;
  }
  if (res.status === 403) {
    await askForPassword(key, await res.json());
    return;
  }
  if (!res.ok) {
    status.textContent = `Unexpected server error (HTTP ${res.status}). Try again.`;
    reveal.disabled = false;
    submit.disabled = false;
    return;
  }
  const body = await res.json();
  clearFragment();
  reveal.hidden = true;
  form.hidden = true;
  try {
    secret.textContent = await decrypt(key, b64urlDecode(body.iv), b64urlDecode(body.ciphertext));
    secret.hidden = false;
    status.textContent = "Secret opened. It is now deleted from the server.";
  } catch {
    status.textContent =
      "Could not decrypt. The link is damaged or the secret was altered. It is deleted from the server.";
  }
}

/**
 * The server wants a password (first ask) or refused the one sent.
 * @param {import("./vault-crypto.js").Bytes} key
 * @param {{error: string, iterations?: number, attempts_left?: number}} answer
 */
async function askForPassword(key, answer) {
  reveal.hidden = true;
  if (answer.error === "wrong_password" && answer.attempts_left === 0) {
    clearFragment();
    form.hidden = true;
    status.textContent = "Wrong password. The secret is deleted from the server.";
    return;
  }
  if (answer.error === "wrong_password") {
    status.textContent = `Wrong password. ${answer.attempts_left} attempts left.`;
  } else {
    iterations = Number(answer.iterations);
    status.textContent = "This secret needs a password.";
  }
  form.hidden = false;
  submit.disabled = false;
  password.value = "";
  password.focus();
  form.onsubmit = async (event) => {
    event.preventDefault();
    submit.disabled = true;
    status.textContent = "Checking the password.";
    const verifier = await passwordVerifier(password.value, key, iterations);
    password.value = "";
    await revealSecret(key, verifier);
  };
}

/** Shows what the current address allows: reveal with a whole key, else "incomplete link". */
function render() {
  if (finished || !form.hidden) return; // done, or already asking for the password
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
  reveal.onclick = () => revealSecret(key, null);
}

render();
// Pasting the missing part into the address bar changes only the fragment: no page reload.
addEventListener("hashchange", render);
