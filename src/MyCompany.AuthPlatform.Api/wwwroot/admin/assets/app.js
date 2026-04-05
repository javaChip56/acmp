import {
  apiRequest,
  clearSession,
  csvToList,
  downloadFromApi,
  fetchSystemInfo,
  formatDateTime,
  formatEnum,
  getRoles,
  hasRole,
  requireSession,
  toLocalDateTimeInputValue,
} from "./auth.js";

const state = {
  session: null,
  systemInfo: null,
  health: null,
  readiness: null,
  clients: [],
  selectedClientId: null,
  selectedClientName: null,
  credentials: [],
  adminUsers: [],
  audit: [],
};

const elements = {
  body: document.body,
  sectionTitle: document.getElementById("section-title"),
  sectionSubtitle: document.getElementById("section-subtitle"),
  navItems: [...document.querySelectorAll("[data-section-target]")],
  logoutButton: document.getElementById("logout-button"),
  refreshButton: document.getElementById("refresh-button"),
  menuToggle: document.getElementById("menu-toggle"),
  alertHost: document.getElementById("alert-host"),
  authModeBadge: document.getElementById("auth-mode-badge"),
  persistenceBadge: document.getElementById("persistence-badge"),
  roleBadge: document.getElementById("role-badge"),
  userDisplay: document.getElementById("user-display"),
  systemNotes: document.getElementById("system-notes"),
  healthStatus: document.getElementById("health-status"),
  readyStatus: document.getElementById("ready-status"),
  clientsCount: document.getElementById("clients-count"),
  usersCount: document.getElementById("users-count"),
  auditCount: document.getElementById("audit-count"),
  readinessList: document.getElementById("readiness-list"),
  clientTableBody: document.getElementById("client-table-body"),
  clientDetailName: document.getElementById("client-detail-name"),
  clientDetailMeta: document.getElementById("client-detail-meta"),
  credentialTableBody: document.getElementById("credential-table-body"),
  adminUserTableBody: document.getElementById("admin-user-table-body"),
  auditTableBody: document.getElementById("audit-table-body"),
  createClientForm: document.getElementById("create-client-form"),
  issueCredentialForm: document.getElementById("issue-credential-form"),
  createAdminUserForm: document.getElementById("create-admin-user-form"),
};

document.addEventListener("DOMContentLoaded", async () => {
  state.session = requireSession();
  initializeStaticView();
  wireEvents();

  try {
    await bootstrapPortal();
  } catch (error) {
    showAlert(error.message ?? "Unable to initialize the portal.", "danger");
  }
});

function initializeStaticView() {
  elements.authModeBadge.textContent = state.session.mode;
  elements.roleBadge.textContent = getRoles(state.session).join(", ") || "Role unknown";
  elements.userDisplay.textContent = state.session.displayName ?? state.session.username ?? state.session.actor ?? "Signed in";
  elements.issueCredentialForm.querySelector("[name='expiresAt']").value = toLocalDateTimeInputValue(90);

  if (state.session.roles?.length > 0 && !hasRole(state.session, "AccessAdministrator")) {
    document.querySelector("[data-section-target='users']")?.closest(".nav-item")?.setAttribute("hidden", "hidden");
    document.querySelector("[data-section-target='audit']")?.closest(".nav-item")?.setAttribute("hidden", "hidden");
  }
}

function wireEvents() {
  for (const navItem of elements.navItems) {
    navItem.addEventListener("click", event => {
      event.preventDefault();
      switchSection(navItem.dataset.sectionTarget);
    });
  }

  elements.logoutButton.addEventListener("click", event => {
    event.preventDefault();
    clearSession();
    window.location.href = "/admin/login.html";
  });

  elements.refreshButton.addEventListener("click", async () => {
    await refreshCurrentSection();
  });

  elements.menuToggle.addEventListener("click", event => {
    event.preventDefault();
    elements.body.classList.toggle("sidebar-collapse");
  });

  elements.createClientForm.addEventListener("submit", async event => {
    event.preventDefault();
    const formData = new FormData(elements.createClientForm);
    const request = {
      clientCode: String(formData.get("clientCode") ?? ""),
      clientName: String(formData.get("clientName") ?? ""),
      owner: String(formData.get("owner") ?? ""),
      environment: String(formData.get("environment") ?? ""),
      description: String(formData.get("description") ?? "") || null,
      metadataJson: null,
    };

    await apiRequest("/api/clients", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    });

    elements.createClientForm.reset();
    showAlert("Client created.", "success");
    await loadClients(true);
  });

  elements.issueCredentialForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (!state.selectedClientId) {
      showAlert("Select a client first.", "warning");
      return;
    }

    const formData = new FormData(elements.issueCredentialForm);
    const request = {
      expiresAt: new Date(String(formData.get("expiresAt"))).toISOString(),
      scopes: csvToList(String(formData.get("scopes") ?? "")),
      notes: String(formData.get("notes") ?? "") || null,
      keyId: String(formData.get("keyId") ?? "") || null,
      keyVersion: String(formData.get("keyVersion") ?? "") || null,
    };

    await apiRequest(`/api/clients/${state.selectedClientId}/credentials/hmac`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    });

    elements.issueCredentialForm.reset();
    elements.issueCredentialForm.querySelector("[name='expiresAt']").value = toLocalDateTimeInputValue(90);
    showAlert("HMAC credential issued.", "success");
    await loadCredentials(state.selectedClientId, state.selectedClientName);
  });

  elements.createAdminUserForm.addEventListener("submit", async event => {
    event.preventDefault();
    const formData = new FormData(elements.createAdminUserForm);
    const roles = [...elements.createAdminUserForm.querySelectorAll("input[name='roles']:checked")].map(
      checkbox => checkbox.value);

    const request = {
      username: String(formData.get("username") ?? ""),
      displayName: String(formData.get("displayName") ?? ""),
      password: String(formData.get("password") ?? ""),
      roles,
    };

    await apiRequest("/api/admin/users", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    });

    elements.createAdminUserForm.reset();
    showAlert("Administrative user created.", "success");
    await loadAdminUsers();
  });

  document.getElementById("client-refresh-button").addEventListener("click", () => loadClients(false));
  document.getElementById("credential-refresh-button").addEventListener("click", () => {
    if (!state.selectedClientId) {
      showAlert("Select a client first.", "warning");
      return;
    }

    return loadCredentials(state.selectedClientId, state.selectedClientName);
  });
  document.getElementById("admin-user-refresh-button").addEventListener("click", () => loadAdminUsers());
  document.getElementById("audit-refresh-button").addEventListener("click", () => loadAudit());
}

async function bootstrapPortal() {
  state.systemInfo = await fetchSystemInfo();
  elements.persistenceBadge.textContent = state.systemInfo.persistenceProvider;
  renderSystemNotes(state.systemInfo.notes ?? []);

  await loadOverview();
  await loadClients(false);

  if (hasRole(state.session, "AccessAdministrator") || getRoles(state.session).length === 0) {
    await Promise.allSettled([loadAdminUsers(), loadAudit()]);
  }

  switchSection("dashboard");
}

function renderSystemNotes(notes) {
  elements.systemNotes.innerHTML = "";
  for (const note of notes) {
    const item = document.createElement("li");
    item.textContent = note;
    elements.systemNotes.append(item);
  }
}

async function loadOverview() {
  const [health, readiness] = await Promise.all([
    apiRequest("/health"),
    apiRequest("/ready"),
  ]);

  state.health = health;
  state.readiness = readiness;
  elements.healthStatus.textContent = health.status;
  elements.readyStatus.textContent = readiness.status;
  renderReadiness(readiness.checks ?? []);
}

async function loadClients(selectFirst) {
  state.clients = await apiRequest("/api/clients");
  elements.clientsCount.textContent = String(state.clients.length);
  renderClientTable();

  if ((selectFirst || state.selectedClientId === null) && state.clients.length > 0) {
    const firstClient = state.clients[0];
    await loadCredentials(firstClient.clientId, firstClient.clientName);
  } else if (state.selectedClientId) {
    const selected = state.clients.find(client => client.clientId === state.selectedClientId);
    if (selected) {
      await loadCredentials(selected.clientId, selected.clientName);
    }
  }
}

function renderClientTable() {
  elements.clientTableBody.innerHTML = "";

  if (state.clients.length === 0) {
    elements.clientTableBody.innerHTML = `<tr><td colspan="7" class="text-center text-body-secondary">No clients found.</td></tr>`;
    return;
  }

  for (const client of state.clients) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><span class="admin-code">${escapeHtml(client.clientCode)}</span></td>
      <td>${escapeHtml(client.clientName)}</td>
      <td>${escapeHtml(client.owner)}</td>
      <td>${escapeHtml(formatEnum(client.environment))}</td>
      <td><span class="badge text-bg-light border">${escapeHtml(formatEnum(client.status))}</span></td>
      <td>${escapeHtml(formatDateTime(client.updatedAt))}</td>
      <td class="text-end">
        <button type="button" class="btn btn-sm btn-outline-primary">Credentials</button>
      </td>
    `;

    row.querySelector("button").addEventListener("click", async () => {
      await loadCredentials(client.clientId, client.clientName);
      switchSection("clients");
    });

    elements.clientTableBody.append(row);
  }
}

async function loadCredentials(clientId, clientName) {
  state.selectedClientId = clientId;
  state.selectedClientName = clientName;
  const response = await apiRequest(`/api/clients/${clientId}/credentials`);
  state.credentials = response.items ?? [];
  elements.clientDetailName.textContent = clientName ?? response.clientName ?? "Selected client";
  elements.clientDetailMeta.textContent = `${response.clientCode} | ${response.items.length} credential(s)`;
  renderCredentialTable();
}

function renderCredentialTable() {
  elements.credentialTableBody.innerHTML = "";

  if (state.credentials.length === 0) {
    elements.credentialTableBody.innerHTML = `<tr><td colspan="8" class="text-center text-body-secondary">No credentials issued for the selected client.</td></tr>`;
    return;
  }

  for (const credential of state.credentials) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td><span class="admin-code">${escapeHtml(credential.keyId ?? "n/a")}</span></td>
      <td>${escapeHtml(credential.keyVersion ?? "n/a")}</td>
      <td>${escapeHtml(formatEnum(credential.status))}</td>
      <td>${escapeHtml((credential.scopes ?? []).join(", ") || "n/a")}</td>
      <td>${escapeHtml(formatDateTime(credential.expiresAt))}</td>
      <td>${escapeHtml(formatDateTime(credential.rotationGraceEndsAt))}</td>
      <td>${escapeHtml(formatDateTime(credential.updatedAt))}</td>
      <td class="text-end">
        <div class="btn-group btn-group-sm">
          <button type="button" class="btn btn-outline-primary" data-action="rotate">Rotate</button>
          <button type="button" class="btn btn-outline-danger" data-action="revoke">Revoke</button>
          <button type="button" class="btn btn-outline-secondary" data-action="service-package">Svc Pkg</button>
          <button type="button" class="btn btn-outline-secondary" data-action="client-package">Client Pkg</button>
        </div>
      </td>
    `;

    row.querySelector("[data-action='rotate']").addEventListener("click", () => rotateCredential(credential));
    row.querySelector("[data-action='revoke']").addEventListener("click", () => revokeCredential(credential));
    row.querySelector("[data-action='service-package']").addEventListener("click", () => issuePackage(credential, false));
    row.querySelector("[data-action='client-package']").addEventListener("click", () => issuePackage(credential, true));
    elements.credentialTableBody.append(row);
  }
}

async function rotateCredential(credential) {
  const expiresAt = prompt("New expiry (ISO 8601)", credential.expiresAt ?? new Date(Date.now() + 90 * 86400000).toISOString());
  if (!expiresAt) {
    return;
  }

  const gracePeriodEndsAt = prompt("Grace period end (ISO 8601, optional)", credential.rotationGraceEndsAt ?? "");
  const scopes = prompt("Scopes (comma separated)", (credential.scopes ?? []).join(", "));
  const notes = prompt("Notes", credential.notes ?? "");
  const newKeyId = prompt("New KeyId", credential.keyId ? `${credential.keyId}-next` : "");
  const newKeyVersion = prompt("New KeyVersion", credential.keyVersion ?? "");
  const reason = prompt("Reason", "Credential rotation");

  await apiRequest(`/api/credentials/${credential.credentialId}/rotate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      expiresAt,
      gracePeriodEndsAt: gracePeriodEndsAt || null,
      scopes: csvToList(scopes ?? ""),
      notes: notes || null,
      newKeyId: newKeyId || null,
      newKeyVersion: newKeyVersion || null,
      reason: reason || null,
    }),
  });

  showAlert(`Credential ${credential.keyId ?? credential.credentialId} rotated.`, "success");
  await loadCredentials(state.selectedClientId, state.selectedClientName);
}

async function revokeCredential(credential) {
  const reason = prompt("Reason for revocation", "Credential no longer required");
  if (!reason) {
    return;
  }

  await apiRequest(`/api/credentials/${credential.credentialId}/revoke`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ reason }),
  });

  showAlert(`Credential ${credential.keyId ?? credential.credentialId} revoked.`, "success");
  await loadCredentials(state.selectedClientId, state.selectedClientName);
}

async function issuePackage(credential, clientPackage) {
  const certificateThumbprint = prompt("Certificate thumbprint", "");
  if (!certificateThumbprint) {
    return;
  }

  const storeLocation = prompt("Certificate store location", "CurrentUser");
  const storeName = prompt("Certificate store name", "My");
  const reason = prompt("Reason", clientPackage ? "Client package issuance" : "Service package issuance");

  const path = clientPackage
    ? `/api/credentials/${credential.credentialId}/issue-client-package`
    : `/api/credentials/${credential.credentialId}/issue-encrypted-package`;

  await downloadFromApi(path, {
    certificateThumbprint,
    storeLocation: storeLocation || "CurrentUser",
    storeName: storeName || "My",
    reason: reason || null,
  });

  showAlert(`${clientPackage ? "Client" : "Service"} package downloaded.`, "success");
}

async function loadAdminUsers() {
  try {
    state.adminUsers = await apiRequest("/api/admin/users");
    elements.usersCount.textContent = String(state.adminUsers.length);
    renderAdminUserTable();
  } catch (error) {
    elements.usersCount.textContent = "n/a";
    elements.adminUserTableBody.innerHTML = `<tr><td colspan="7" class="text-center text-body-secondary">${escapeHtml(error.message)}</td></tr>`;
  }
}

function renderAdminUserTable() {
  elements.adminUserTableBody.innerHTML = "";

  if (state.adminUsers.length === 0) {
    elements.adminUserTableBody.innerHTML = `<tr><td colspan="7" class="text-center text-body-secondary">No administrative users found.</td></tr>`;
    return;
  }

  for (const user of state.adminUsers) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${escapeHtml(user.username)}</td>
      <td>${escapeHtml(user.displayName)}</td>
      <td>${escapeHtml((user.roles ?? []).join(", "))}</td>
      <td>${escapeHtml(formatEnum(user.status))}</td>
      <td>${escapeHtml(formatDateTime(user.lastLoginAt))}</td>
      <td>${escapeHtml(formatDateTime(user.updatedAt))}</td>
      <td class="text-end">
        <div class="btn-group btn-group-sm">
          <button type="button" class="btn btn-outline-primary" data-action="roles">Roles</button>
          <button type="button" class="btn btn-outline-secondary" data-action="password">Password</button>
          <button type="button" class="btn btn-outline-danger" data-action="disable">Disable</button>
        </div>
      </td>
    `;

    row.querySelector("[data-action='roles']").addEventListener("click", () => updateUserRoles(user));
    row.querySelector("[data-action='password']").addEventListener("click", () => resetUserPassword(user));
    row.querySelector("[data-action='disable']").addEventListener("click", () => disableUser(user));
    elements.adminUserTableBody.append(row);
  }
}

async function updateUserRoles(user) {
  const roles = prompt("Roles (comma separated)", (user.roles ?? []).join(", "));
  if (roles === null) {
    return;
  }

  const reason = prompt("Reason", "Role update");
  await apiRequest(`/api/admin/users/${user.userId}/roles`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      roles: csvToList(roles),
      reason: reason || null,
    }),
  });

  showAlert(`Roles updated for ${user.username}.`, "success");
  await loadAdminUsers();
}

async function resetUserPassword(user) {
  const newPassword = prompt(`New password for ${user.username}`, "ChangeMe!123");
  if (!newPassword) {
    return;
  }

  const reason = prompt("Reason", "Password reset");
  await apiRequest(`/api/admin/users/${user.userId}/reset-password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      newPassword,
      reason: reason || null,
    }),
  });

  showAlert(`Password reset for ${user.username}.`, "success");
}

async function disableUser(user) {
  const reason = prompt("Reason", "Administrative user disabled");
  if (reason === null) {
    return;
  }

  await apiRequest(`/api/admin/users/${user.userId}/disable`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      reason: reason || null,
    }),
  });

  showAlert(`User ${user.username} disabled.`, "success");
  await loadAdminUsers();
}

async function loadAudit() {
  try {
    state.audit = await apiRequest("/api/audit");
    elements.auditCount.textContent = String(state.audit.length);
    renderAuditTable();
  } catch (error) {
    elements.auditCount.textContent = "n/a";
    elements.auditTableBody.innerHTML = `<tr><td colspan="6" class="text-center text-body-secondary">${escapeHtml(error.message)}</td></tr>`;
  }
}

function renderAuditTable() {
  elements.auditTableBody.innerHTML = "";

  if (state.audit.length === 0) {
    elements.auditTableBody.innerHTML = `<tr><td colspan="6" class="text-center text-body-secondary">No audit entries available.</td></tr>`;
    return;
  }

  for (const entry of state.audit.slice(0, 200)) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${escapeHtml(formatDateTime(entry.timestamp))}</td>
      <td>${escapeHtml(entry.actor)}</td>
      <td>${escapeHtml(entry.action)}</td>
      <td>${escapeHtml(entry.targetType)}${entry.targetId ? `<div class="small text-body-secondary">${escapeHtml(entry.targetId)}</div>` : ""}</td>
      <td>${escapeHtml(entry.reason ?? "")}</td>
      <td><pre class="admin-metadata">${escapeHtml(entry.metadataJson ?? "")}</pre></td>
    `;
    elements.auditTableBody.append(row);
  }
}

function renderReadiness(checks) {
  elements.readinessList.innerHTML = "";
  for (const check of checks) {
    const item = document.createElement("li");
    item.className = "list-group-item d-flex justify-content-between align-items-start";
    item.innerHTML = `
      <div>
        <div class="fw-semibold">${escapeHtml(check.name)}</div>
        <div class="text-body-secondary small">${escapeHtml(check.details)}</div>
      </div>
      <span class="badge ${check.status === "Ready" ? "text-bg-success" : "text-bg-danger"}">${escapeHtml(check.status)}</span>
    `;
    elements.readinessList.append(item);
  }
}

function switchSection(target) {
  const sections = [...document.querySelectorAll(".admin-section")];
  sections.forEach(section => section.hidden = section.dataset.section !== target);
  elements.navItems.forEach(item => {
    const active = item.dataset.sectionTarget === target;
    item.classList.toggle("active", active);
  });

  const current = document.querySelector(`.admin-section[data-section='${target}']`);
  elements.sectionTitle.textContent = current?.dataset.title ?? "Admin";
  elements.sectionSubtitle.textContent = current?.dataset.subtitle ?? "";
}

async function refreshCurrentSection() {
  const current = document.querySelector(".admin-section:not([hidden])");
  const section = current?.dataset.section ?? "dashboard";

  if (section === "dashboard") {
    await Promise.allSettled([loadOverview(), loadClients(false)]);
    if (hasRole(state.session, "AccessAdministrator") || getRoles(state.session).length === 0) {
      await Promise.allSettled([loadAdminUsers(), loadAudit()]);
    }
    showAlert("Dashboard refreshed.", "success");
    return;
  }

  if (section === "clients") {
    await loadClients(false);
    showAlert("Clients refreshed.", "success");
    return;
  }

  if (section === "users") {
    await loadAdminUsers();
    showAlert("Administrative users refreshed.", "success");
    return;
  }

  if (section === "audit") {
    await loadAudit();
    showAlert("Audit log refreshed.", "success");
  }
}

function showAlert(message, tone) {
  const wrapper = document.createElement("div");
  wrapper.className = `alert alert-${tone} alert-dismissible fade show`;
  wrapper.setAttribute("role", "alert");
  wrapper.innerHTML = `
    ${escapeHtml(message)}
    <button type="button" class="btn-close" aria-label="Close"></button>
  `;

  wrapper.querySelector("button").addEventListener("click", () => wrapper.remove());
  elements.alertHost.prepend(wrapper);

  setTimeout(() => wrapper.remove(), 6000);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
