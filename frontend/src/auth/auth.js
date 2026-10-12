/**
 * Frontend authentication service wrapping /api/auth endpoints.
 */

import { apiRequest, ensureCsrfToken } from "../api/client.js";
import { validateAuthCredentials } from "../utils/validation.js";

/**
 * Bootstrap CSRF token and check if the user already has an active server session.
 * @returns {Promise<object|null>} User profile object or null if unauthenticated
 */
export async function checkCurrentSession() {
  await ensureCsrfToken();
  try {
    const data = await apiRequest("/api/auth/me", { method: "GET" });
    return data.user || null;
  } catch (err) {
    if (err.status === 401) {
      return null;
    }
    throw err;
  }
}

/**
 * Register a new user account.
 */
export async function registerAccount({ email, loginPassword }) {
  const validated = validateAuthCredentials({
    email,
    loginPassword,
    isRegistration: true,
  });

  const data = await apiRequest("/api/auth/register", {
    method: "POST",
    body: {
      email: validated.email,
      login_password: validated.loginPassword,
    },
  });

  return data.user;
}

/**
 * Authenticate an existing user account.
 */
export async function loginAccount({ email, loginPassword }) {
  const validated = validateAuthCredentials({
    email,
    loginPassword,
    isRegistration: false,
  });

  const data = await apiRequest("/api/auth/login", {
    method: "POST",
    body: {
      email: validated.email,
      login_password: validated.loginPassword,
    },
  });

  return data.user;
}

/**
 * Log out and invalidate the server-side session.
 */
export async function logoutAccount() {
  await apiRequest("/api/auth/logout", {
    method: "POST",
    body: {},
  });
}
