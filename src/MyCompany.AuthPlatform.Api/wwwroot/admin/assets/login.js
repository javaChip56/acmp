import {
  clearSession,
  fetchSystemInfo,
  getSession,
  saveSession,
} from "./auth.js";

const authModeName = document.getElementById("auth-mode-name");
const authModeHelp = document.getElementById("auth-mode-help");
const loginFormHost = document.getElementById("login-form-host");
const loginMessage = document.getElementById("login-message");
const systemNotes = document.getElementById("system-notes");

document.addEventListener("DOMContentLoaded", async () => {
  const existingSession = getSession();
  if (existingSession) {
    window.location.href = "/admin/index.html";
    return;
  }

  clearSession();

  try {
    const systemInfo = await fetchSystemInfo();
    renderNotes(systemInfo.notes ?? []);
    renderLoginForm(systemInfo.authenticationMode);
  } catch (error) {
    showMessage(error.message ?? "Unable to load login mode.", "danger");
  }
});

function renderNotes(notes) {
  systemNotes.innerHTML = "";
  for (const note of notes) {
    const item = document.createElement("li");
    item.textContent = note;
    systemNotes.append(item);
  }
}

function renderLoginForm(mode) {
  authModeName.textContent = mode;
  loginFormHost.innerHTML = "";

  if (mode === "EmbeddedIdentity") {
    authModeHelp.textContent = "Use one of the configured embedded admin users to sign in.";
    loginFormHost.append(createEmbeddedIdentityForm());
    return;
  }

  if (mode === "DemoHeader") {
    authModeHelp.textContent = "Choose a demo role and actor name. The portal will send the demo headers for each request.";
    loginFormHost.append(createDemoHeaderForm());
    return;
  }

  authModeHelp.textContent = "Paste a bearer token issued by your identity provider.";
  loginFormHost.append(createJwtForm());
}

function createEmbeddedIdentityForm() {
  const form = document.createElement("form");
  form.className = "admin-form-stack";
  form.innerHTML = `
    <div>
      <label class="form-label" for="username">Username</label>
      <div class="input-group">
        <input id="username" name="username" class="form-control" value="administrator.demo" autocomplete="username" required />
        <span class="input-group-text"><i class="bi bi-person"></i></span>
      </div>
    </div>
    <div>
      <label class="form-label" for="password">Password</label>
      <div class="input-group">
        <input id="password" name="password" type="password" class="form-control" value="AdministratorPass!123" autocomplete="current-password" required />
        <span class="input-group-text"><i class="bi bi-shield-lock"></i></span>
      </div>
    </div>
    <button type="submit" class="btn btn-primary w-100">Sign In</button>
    <div class="small text-body-secondary">
      Demo accounts are preconfigured in <code>appsettings.Development.json</code>.
    </div>
  `;

  form.addEventListener("submit", async event => {
    event.preventDefault();
    clearMessage();

    const formData = new FormData(form);
    const payload = {
      username: String(formData.get("username") ?? ""),
      password: String(formData.get("password") ?? ""),
    };

    try {
      const response = await fetch("/api/auth/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message ?? "Sign-in failed.");
      }

      const token = await response.json();
      saveSession({
        mode: "EmbeddedIdentity",
        accessToken: token.accessToken,
        expiresAt: token.expiresAt,
        username: token.username,
        displayName: token.displayName,
        roles: token.roles ?? [],
      });
      window.location.href = "/admin/index.html";
    } catch (error) {
      showMessage(error.message ?? "Unable to sign in.", "danger");
    }
  });

  return form;
}

function createDemoHeaderForm() {
  const form = document.createElement("form");
  form.className = "admin-form-stack";
  form.innerHTML = `
    <div>
      <label class="form-label" for="demo-actor">Actor</label>
      <div class="input-group">
        <input id="demo-actor" name="actor" class="form-control" value="demo.admin" required />
        <span class="input-group-text"><i class="bi bi-person-badge"></i></span>
      </div>
    </div>
    <div>
      <label class="form-label" for="demo-role">Role</label>
      <select id="demo-role" name="role" class="form-select">
        <option value="AccessAdministrator">AccessAdministrator</option>
        <option value="AccessOperator">AccessOperator</option>
        <option value="AccessViewer">AccessViewer</option>
      </select>
    </div>
    <button type="submit" class="btn btn-primary w-100">Continue</button>
  `;

  form.addEventListener("submit", event => {
    event.preventDefault();
    clearMessage();

    const formData = new FormData(form);
    const role = String(formData.get("role") ?? "AccessViewer");
    const actor = String(formData.get("actor") ?? "demo.user");
    saveSession({
      mode: "DemoHeader",
      actor,
      role,
      roles: [role],
      displayName: actor,
    });
    window.location.href = "/admin/index.html";
  });

  return form;
}

function createJwtForm() {
  const form = document.createElement("form");
  form.className = "admin-form-stack";
  form.innerHTML = `
    <div>
      <label class="form-label" for="jwt-display-name">Display Name</label>
      <input id="jwt-display-name" name="displayName" class="form-control" value="JWT Operator" />
    </div>
    <div>
      <label class="form-label" for="jwt-token">Bearer Token</label>
      <textarea id="jwt-token" name="token" class="form-control admin-token-box" required></textarea>
    </div>
    <button type="submit" class="btn btn-primary w-100">Continue</button>
  `;

  form.addEventListener("submit", event => {
    event.preventDefault();
    clearMessage();

    const formData = new FormData(form);
    saveSession({
      mode: "JwtBearer",
      accessToken: String(formData.get("token") ?? ""),
      displayName: String(formData.get("displayName") ?? "JWT User"),
      roles: [],
    });
    window.location.href = "/admin/index.html";
  });

  return form;
}

function showMessage(message, tone) {
  loginMessage.className = `alert alert-${tone}`;
  loginMessage.textContent = message;
  loginMessage.hidden = false;
}

function clearMessage() {
  loginMessage.hidden = true;
  loginMessage.textContent = "";
}
