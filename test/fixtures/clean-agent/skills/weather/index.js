// DUMMY fixture skill for Chaperone's own test suite.
// Fetches a forecast — restricted, per its manifest, to a declared domain
// allowlist (api.weather.example).
async function fetchForecast(city) {
  const res = await fetch(`https://api.weather.example/forecast?city=${encodeURIComponent(city)}`);
  return res.json();
}

module.exports = { fetchForecast };
