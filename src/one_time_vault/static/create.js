// @ts-check
import { byId } from "./dom.js";
import { MAX_TEXT_BYTES, b64urlEncode, encrypt, newKey } from "./vault-crypto.js";

const form = byId("create-form", HTMLFormElement);
const text = byId("text", HTMLTextAreaElement);
const button = byId("create", HTMLButtonElement);
const error = byId("error", HTMLElement);
const result = byId("result", HTMLElement);
const link = byId("link", HTMLInputElement);
const copy = byId("copy", HTMLButtonElement);

/** @param {string} message */
function fail(message) {
  error.textContent = message;
  error.hidden = false;
  button.disabled = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  error.hidden = true;
  button.disabled = true;
  const size = new TextEncoder().encode(text.value).length;
  if (size === 0) return fail("Write a secret first.");
  if (size > MAX_TEXT_BYTES) return fail("The secret is longer than 10 KB.");
  const expiresIn = new FormData(form).get("expires_in");
  try {
    const key = newKey();
    const { iv, ciphertext } = await encrypt(text.value, key);
    const res = await fetch("/api/secrets", {
      method: "POST",
      headers: { "content-type": "application/json" },
      referrerPolicy: "no-referrer",
      body: JSON.stringify({
        iv: b64urlEncode(iv),
        ciphertext: b64urlEncode(ciphertext),
        expires_in: expiresIn,
      }),
    });
    if (!res.ok) return fail(`The server refused the secret (HTTP ${res.status}).`);
    const { id } = await res.json();
    link.value = `${location.origin}/s/${id}#${b64urlEncode(key)}`;
    result.hidden = false;
    text.value = "";
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
  } catch {
    copy.textContent = "Press Ctrl+C";
  }
});
