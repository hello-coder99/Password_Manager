/**
 * Same-origin REST API client with automatic CSRF header management.
 * Never persists tokens or secrets in localStorage or sessionStorage.
 */

let csrfTokenMemory = null;

export class ApiError extends Error {
  constructor(message, status, code = "API_ERROR", details = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function setCsrfToken(token) {
  if (typeof token === "string" && token.trim().length > 0) {
    csrfTokenMemory = token.trim();
  }
}

export function getCsrfToken() {
  return csrfTokenMemory;
}

/**
 * Ensure a valid CSRF token is loaded into memory before state-changing requests.
 */
export async function ensureCsrfToken() {
  if (csrfTokenMemory) {
    return csrfTokenMemory;
  }
  const response = await fetch("/api/csrf-token", {
    method: "GET",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
    },
  });
  if (!response.ok) {
    throw new ApiError(
      "Unable to initialize CSRF protection token.",
      response.status,
      "CSRF_INIT_FAILED"
    );
  }
  const data = await response.json();
  setCsrfToken(data.csrf_token);
  return csrfTokenMemory;
}

/**
 * Perform a same-origin JSON API request.
 */
export async function apiRequest(path, { method = "GET", body = undefined } = {}) {
  const upperMethod = method.toUpperCase();
  const isStateChanging = ["POST", "PUT", "PATCH", "DELETE"].includes(upperMethod);

  if (isStateChanging && !csrfTokenMemory) {
    await ensureCsrfToken();
  }

  const headers = {
    Accept: "application/json",
  };

  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  if (isStateChanging && csrfTokenMemory) {
    headers["X-CSRF-Token"] = csrfTokenMemory;
  }

  const response = await fetch(path, {
    method: upperMethod,
    credentials: "same-origin",
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  let payload = null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
  }

  // Update in-memory CSRF token whenever the backend rotates and returns a new one
  if (payload && typeof payload.csrf_token === "string") {
    setCsrfToken(payload.csrf_token);
  }

  // If CSRF token expired after session renewal, refresh once and retry
  if (response.status === 400 && payload?.code === "CSRF_ERROR" && isStateChanging) {
    csrfTokenMemory = null;
    await ensureCsrfToken();
    headers["X-CSRF-Token"] = csrfTokenMemory;
    const retryResponse = await fetch(path, {
      method: upperMethod,
      credentials: "same-origin",
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const retryPayload = await retryResponse.json().catch(() => null);
    if (retryPayload && typeof retryPayload.csrf_token === "string") {
      setCsrfToken(retryPayload.csrf_token);
    }
    if (!retryResponse.ok) {
      throw new ApiError(
        formatErrorMessage(retryPayload, retryResponse.status),
        retryResponse.status,
        retryPayload?.code || "API_ERROR",
        retryPayload?.details || null
      );
    }
    return retryPayload;
  }

  if (!response.ok) {
    throw new ApiError(
      formatErrorMessage(payload, response.status),
      response.status,
      payload?.code || "API_ERROR",
      payload?.details || null
    );
  }

  return payload;
}

function formatErrorMessage(payload, status) {
  if (!payload) {
    return `Request failed with HTTP status ${status}.`;
  }
  if (payload.details && typeof payload.details === "object") {
    const firstField = Object.keys(payload.details)[0];
    const fieldErrors = payload.details[firstField];
    if (Array.isArray(fieldErrors) && fieldErrors.length > 0) {
      return String(fieldErrors[0]);
    }
  }
  return payload.error || `Request failed with HTTP status ${status}.`;
}
