const storageKey = "acmp.admin.session";

export async function fetchSystemInfo() {
  const response = await fetch("/api/system/info", {
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error("Unable to load system information.");
  }

  return response.json();
}

export function getSession() {
  const raw = localStorage.getItem(storageKey);
  if (!raw) {
    return null;
  }

  try {
    const session = JSON.parse(raw);
    if (!session || typeof session !== "object") {
      return null;
    }

    if (session.expiresAt && new Date(session.expiresAt).getTime() < Date.now()) {
      clearSession();
      return null;
    }

    return session;
  } catch {
    clearSession();
    return null;
  }
}

export function saveSession(session) {
  localStorage.setItem(storageKey, JSON.stringify(session));
}

export function clearSession() {
  localStorage.removeItem(storageKey);
}

export function requireSession() {
  const session = getSession();
  if (!session) {
    window.location.href = "/admin/login.html";
    throw new Error("Authentication is required.");
  }

  return session;
}

export function getRoles(session) {
  if (!session?.roles || !Array.isArray(session.roles)) {
    return [];
  }

  return session.roles;
}

export function hasRole(session, role) {
  return getRoles(session).includes(role);
}

export function createCorrelationId() {
  if (window.crypto?.randomUUID) {
    return window.crypto.randomUUID();
  }

  return `corr-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function buildAuthHeaders(session) {
  const headers = {
    Accept: "application/json",
    "X-Correlation-Id": createCorrelationId(),
  };

  if (!session) {
    return headers;
  }

  if (session.mode === "EmbeddedIdentity" || session.mode === "JwtBearer") {
    headers.Authorization = `Bearer ${session.accessToken}`;
    return headers;
  }

  if (session.mode === "DemoHeader") {
    headers["X-Demo-Role"] = session.role;
    headers["X-Demo-Actor"] = session.actor;
  }

  return headers;
}

export async function apiRequest(path, options = {}) {
  const session = getSession();
  const headers = {
    ...buildAuthHeaders(session),
    ...(options.headers ?? {}),
  };

  const response = await fetch(path, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    clearSession();
    window.location.href = "/admin/login.html";
    throw new Error("Your session has expired. Please sign in again.");
  }

  const contentType = response.headers.get("content-type") ?? "";
  const isJson = contentType.includes("application/json");

  if (!response.ok) {
    let message = `Request failed with status ${response.status}.`;
    if (isJson) {
      const error = await response.json();
      message = error.message ?? error.errorCode ?? message;
    } else {
      const text = await response.text();
      if (text) {
        message = text;
      }
    }

    const exception = new Error(message);
    exception.status = response.status;
    throw exception;
  }

  if (options.responseType === "blob") {
    return response;
  }

  if (response.status === 204) {
    return null;
  }

  if (isJson) {
    return response.json();
  }

  return response.text();
}

export function formatDateTime(value) {
  if (!value) {
    return "n/a";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function formatEnum(value) {
  if (!value) {
    return "n/a";
  }

  return String(value)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replaceAll("_", " ");
}

export function csvToList(value) {
  if (!value) {
    return [];
  }

  return value
    .split(",")
    .map(item => item.trim())
    .filter(Boolean);
}

export function toLocalDateTimeInputValue(daysAhead = 30) {
  const date = new Date(Date.now() + daysAhead * 24 * 60 * 60 * 1000);
  return date.toISOString().slice(0, 16);
}

export async function downloadFromApi(path, body) {
  const response = await apiRequest(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    responseType: "blob",
  });

  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") ?? "";
  const fallbackName = response.headers.get("X-Package-Id") ?? "package.bin";
  const match = disposition.match(/filename="?([^"]+)"?/i);
  const fileName = match?.[1] ?? fallbackName;
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
