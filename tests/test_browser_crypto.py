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


def test_one_page_load_never_reuses_an_iv_or_a_key_through_the_form(tab: Tab) -> None:
    """Same page, no reload: a value kept in a module variable would repeat here."""
    tab.page.goto(tab.base + "/")
    ivs: list[bytes] = []
    keys: list[bytes] = []
    for _ in range(SECRETS):
        before = tab.page.input_value("#link")
        tab.requests.clear()
        tab.page.fill("#text", "the very same text every time")
        tab.page.click("#create")
        tab.page.wait_for_function(
            "old => document.getElementById('link').value !== old", arg=before
        )
        (post,) = [r for r in tab.requests if r.method == "POST"]
        sent = post.post_data_json
        assert sent is not None
        ivs.append(unb64url(sent["iv"]))
        keys.append(unb64url(tab.page.input_value("#link").split("#", 1)[1]))
    assert len(set(ivs)) == SECRETS, "an IV was used twice on one page load"
    assert len(set(keys)) == SECRETS, "a key was used twice on one page load"


ENCRYPT_MANY_ON_ONE_PAGE = """
async (count) => {
  const m = await import('/static/vault-crypto.js');
  const keys = [];
  const ivs = [];
  const sameKey = m.newKey();
  for (let i = 0; i < count; i++) {
    keys.push(m.b64urlEncode(m.newKey()));
    ivs.push(m.b64urlEncode((await m.encrypt('same text', m.newKey())).iv));
    ivs.push(m.b64urlEncode((await m.encrypt('same text', sameKey)).iv));
  }
  return { keys, ivs };
}
"""


def test_the_encrypt_function_never_repeats_an_iv_or_newkey_a_key_in_one_page(tab: Tab) -> None:
    """Straight at the module, many calls in one load: also with the very same key."""
    tab.page.goto(tab.base + "/")
    count = 20
    out = tab.page.evaluate(ENCRYPT_MANY_ON_ONE_PAGE, count)
    assert len(set(out["keys"])) == count, "newKey repeated a key"
    assert len(out["ivs"]) == 2 * count
    assert len(set(out["ivs"])) == 2 * count, "encrypt repeated an IV"
