const $ = (id) => document.getElementById(id);
let mode = "login";
let currentUser = null;

function showNotice(message, type = "error", target = "notice") {
  const box = $(target);
  box.textContent = message;
  box.className = `notice ${type}`;
}
function clearNotice(target = "notice") {
  $(target).textContent = "";
  $(target).className = "notice hidden";
}
async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || "Request failed.");
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}
function setMode(nextMode) {
  mode = nextMode;
  const registering = mode === "register";
  $("loginTab").classList.toggle("active", !registering);
  $("registerTab").classList.toggle("active", registering);
  $("formKicker").textContent = registering ? "JOIN SECUREGATE" : "WELCOME BACK";
  $("formTitle").textContent = registering ? "Create your account" : "Sign in to your account";
  $("formSubtitle").textContent = registering ? "Set up your user ID and a strong password." : "Enter your credentials to continue securely.";
  $("submitBtn").innerHTML = registering ? 'Create account <span>→</span>' : 'Sign in securely <span>→</span>';
  $("password").autocomplete = registering ? "new-password" : "current-password";
  $("password").minLength = registering ? 8 : 1;
  $("passwordHint").classList.toggle("hidden", !registering);
  clearNotice();
}
async function refreshStatus() {
  try {
    const data = await api("/api/status");
    $("detectedIp").textContent = data.ip;
    const count = data.failedAttempts || 0;
    $("attemptCount").textContent = `${count} / ${data.maxAttempts}`;
    $("attemptBar").style.width = `${Math.min(100, count / data.maxAttempts * 100)}%`;
    $("attemptHint").textContent = data.blockedUntil
      ? `This IP is blocked until ${new Date(data.blockedUntil).toLocaleString()}.`
      : count ? `${data.maxAttempts - count} attempt(s) remaining before an IP block.` : "Your IP is currently clear.";
    if (data.blockedUntil) $("attemptBar").style.background = "#f06b75";
    $("connection").innerHTML = "<i></i> Server connected";
  } catch {
    $("connection").textContent = "Server unavailable";
    $("detectedIp").textContent = "Unavailable";
  }
}
async function showDashboard() {
  const data = await api("/api/me");
  currentUser = data.user;
  $("authView").classList.add("hidden");
  $("dashboardView").classList.remove("hidden");
  $("welcomeTitle").textContent = `Welcome, ${data.user.username}`;
  $("dashUsername").textContent = data.user.username;
  $("avatar").textContent = data.user.username.charAt(0).toUpperCase();
  $("dashIp").textContent = data.ip;
  $("dashRole").textContent = data.user.role === "admin" ? "Administrator" : "Standard user";
  $("dashRoleTile").textContent = data.user.role;
  $("adminPanel").classList.toggle("hidden", data.user.role !== "admin");
  clearNotice("dashNotice");
  if (data.user.role === "admin") await loadAdmin();
}
async function loadAdmin() {
  try {
    const data = await api("/api/admin/overview");
    $("userList").replaceChildren();
    $("blockedList").replaceChildren();
    if (!data.users.length) $("userList").innerHTML = '<div class="empty-row">No registered users.</div>';
    data.users.forEach(user => {
      const row = document.createElement("div");
      row.className = "data-row";
      const name = document.createElement("span");
      name.textContent = user.username;
      const role = document.createElement("span");
      role.textContent = user.role;
      row.append(name, role);
      $("userList").append(row);
    });
    if (!data.blocked.length) $("blockedList").innerHTML = '<div class="empty-row">No active IP blocks.</div>';
    data.blocked.forEach(item => {
      const row = document.createElement("div");
      row.className = "data-row";
      const ip = document.createElement("span");
      ip.textContent = item.ip;
      const until = document.createElement("span");
      until.textContent = new Date(item.blocked_until).toLocaleString();
      row.append(ip, until);
      $("blockedList").append(row);
    });
  } catch (e) { showNotice(e.message, "error", "dashNotice"); }
}
$("loginTab").addEventListener("click", () => setMode("login"));
$("registerTab").addEventListener("click", () => setMode("register"));
$("authForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearNotice();
  const button = $("submitBtn");
  button.disabled = true;
  button.textContent = mode === "register" ? "Creating account…" : "Signing in…";
  try {
    const payload = {
      username: $("username").value.trim(),
      password: $("password").value
    };
    if (mode === "register") {
      const data = await api("/api/register", { method: "POST", body: JSON.stringify(payload) });
      showNotice(data.message, "success");
      $("password").value = "";
      setMode("login");
      showNotice(data.message, "success");
    } else {
      const data = await api("/api/login", { method: "POST", body: JSON.stringify(payload) });
      $("password").value = "";
      await showDashboard();
      await refreshStatus();
    }
  } catch (e) {
    showNotice(e.message, "error");
    if (e.data && e.data.failedAttempts !== undefined) await refreshStatus();
  } finally {
    button.disabled = false;
    button.innerHTML = mode === "register" ? 'Create account <span>→</span>' : 'Sign in securely <span>→</span>';
  }
});
$("logoutBtn").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST", body: "{}" });
    currentUser = null;
    $("dashboardView").classList.add("hidden");
    $("authView").classList.remove("hidden");
    $("username").value = "";
    $("password").value = "";
    setMode("login");
    await refreshStatus();
  } catch (e) { showNotice(e.message, "error", "dashNotice"); }
});
$("securityBtn").addEventListener("click", async () => {
  const box = $("securityDetails");
  if (!box.classList.contains("hidden")) {
    box.classList.add("hidden");
    return;
  }
  try {
    const data = await api("/api/security");
    box.textContent = `Detected IP: ${data.ip} · Failed attempts: ${data.failedAttempts}/${data.maxAttempts} · Block duration: ${data.blockDurationHours} hours.`;
    box.classList.remove("hidden");
  } catch (e) { showNotice(e.message, "error", "dashNotice"); }
});
$("refreshAdmin").addEventListener("click", loadAdmin);

(async function init() {
  await refreshStatus();
  try { await showDashboard(); }
  catch { $("authView").classList.remove("hidden"); }
  setMode("login");
})();
