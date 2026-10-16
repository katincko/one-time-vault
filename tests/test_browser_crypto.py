"""What the browser draws at random, and that the derived AES key cannot leave the page."""

from browser_kit import Tab, unb64url

SECRETS = 4


def test_every_secret_gets_a_fresh_iv_and_key_of_the_right_size(tab: Tab) -> None:
    """A fixed IV or key still round-trips, so only looking at what was made can catch it."""
    ivs: list[bytes] = []
    keys: list[bytes] = []
    ciphertexts: list[bytes] = []
    for _ in range(SECRETS):
        tab.requests.clear()
        link = tab.create("the very same text every time")
        (post,) = [r for r in tab.requests if r.method == "POST"]
        sent = post.post_data_json
        assert sent is not None
        ivs.append(unb64url(sent["iv"]))
        ciphertexts.append(unb64url(sent["ciphertext"]))
        keys.append(unb64url(link.split("#", 1)[1]))
    assert {len(iv) for iv in ivs} == {12}
    assert {len(key) for key in keys} == {32}
    assert len(set(ivs)) == SECRETS, "an IV was used twice"
    assert len(set(keys)) == SECRETS, "a key was used twice"
    assert len(set(ciphertexts)) == SECRETS  # same text, same block count, still different
    assert bytes(12) not in ivs and bytes(32) not in keys
    # a key or IV that is one repeated byte is not 96 or 256 random bits
    assert all(len(set(iv)) > 1 for iv in ivs) and all(len(set(key)) > 8 for key in keys)


EXPORT_THE_AES_KEY = """
async () => {
  const m = await import('/static/vault-crypto.js');
  const { encryption } = await m.deriveKeys(m.newKey());
  let exportError = null;
  try {
    await crypto.subtle.exportKey('raw', encryption);
  } catch (e) {
    exportError = e.name;
  }
  return { extractable: encryption.extractable, usages: encryption.usages, exportError };
}
"""


def test_the_derived_aes_key_is_not_extractable(tab: Tab) -> None:
    tab.page.goto(tab.base + "/")
    out = tab.page.evaluate(EXPORT_THE_AES_KEY)
    assert sorted(out["usages"]) == ["decrypt", "encrypt"]  # a real, usable key
    assert out["extractable"] is False
    assert out["exportError"] == "InvalidAccessError"
