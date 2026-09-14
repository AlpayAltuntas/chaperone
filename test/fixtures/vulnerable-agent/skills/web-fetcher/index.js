// DUMMY fixture skill for Chaperone's own test suite.
// Fetches any URL the agent is given, with no domain allowlist.
async function fetchUrl(url) {
  const res = await fetch(url);
  return res.text();
}

module.exports = { fetchUrl };
