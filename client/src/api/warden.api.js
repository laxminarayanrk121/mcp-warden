const API = import.meta.env.VITE_API_URL || "http://localhost:4000/api";
async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, { ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body?.error?.message || `Request failed (${response.status})`);
  return body;
}
export const getHealth = () => request("/health");
export const getFixtures = () => request("/fixtures");
export const getBaselines = () => request("/baselines");
export const scanFixture = (fixtureId) => request("/scan", { method: "POST", body: JSON.stringify({ fixtureId }) });
export const saveBaseline = (fixtureId) => request("/baselines", { method: "POST", body: JSON.stringify({ fixtureId }) });
export const compareFixture = (baselineId, fixtureId) => request("/compare", { method: "POST", body: JSON.stringify({ baselineId, fixtureId }) });
