// @ts-check
import { byId } from "./dom.js";
import {
  MAX_TEXT_BYTES,
  PBKDF2_ITERATIONS,
  b64urlEncode,
  encrypt,
  newKey,
  passwordVerifier,
} from "./vault-crypto.js";

const form = byId("create-form", HTMLFormElement);
const text = byId("text", HTMLTextAreaElement);
const password = byId("password", HTMLInputElement);
const button = byId("create", HTMLButtonElement);
const error = byId("error", HTMLElement);
const errorText = byId("error-text", HTMLElement);
const result = byId("result", HTMLElement);
const link = byId("link", HTMLInputElement);
const copy = byId("copy", HTMLButtonElement);

form.hidden = false; // hidden in the HTML so that without JavaScript only the noscript error shows

/** Put the Copy button back to its first look (a new link, or a copy that did not work). */
function resetCopy() {
  copy.textContent = "Copy";
  copy.classList.remove("done");
}

/** @param {string} message */
function fail(message) {
  errorText.textContent = message;
  error.hidden = false;
  button.disabled = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  error.hidden = true;
  button.disabled = true;
  resetCopy();
  const size = new TextEncoder().encode(text.value).length;
  if (size === 0) {
    text.focus();
    return fail("Write a secret first.");
  }
  if (size > MAX_TEXT_BYTES) return fail("The secret is longer than 10 KB.");
  const expiresIn = new FormData(form).get("expires_in");
  try {
    const key = newKey();
    const { iv, ciphertext } = await encrypt(text.value, key);
    const protectedBy =
      password.value === ""
        ? {}
        : {
            password_verifier: b64urlEncode(
              await passwordVerifier(password.value, key, PBKDF2_ITERATIONS),
            ),
            iterations: PBKDF2_ITERATIONS,
          };
    const res = await fetch("/api/secrets", {
      method: "POST",
      headers: { "content-type": "application/json" },
      referrerPolicy: "no-referrer",
      body: JSON.stringify({
        iv: b64urlEncode(iv),
        ciphertext: b64urlEncode(ciphertext),
        expires_in: expiresIn,
        ...protectedBy,
      }),
    });
    if (!res.ok) return fail(`The server refused the secret (HTTP ${res.status}).`);
    const { id } = await res.json();
    link.value = `${location.origin}/s/${id}#${b64urlEncode(key)}`;
    result.hidden = false;
    text.value = "";
    password.value = "";
    button.disabled = false;
  } catch {
    fail("Could not create the secret. Check your connection and try again.");
  }
});

copy.addEventListener("click", async () => {
  link.select();
  try {
    await navigator.clipboard.writeText(link.value);
    copy.textContent = "Copied";
    copy.classList.add("done");
  } catch {
    resetCopy();
    copy.textContent = "Press Ctrl+C";
  }
});
