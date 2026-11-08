import {
  cert,
  getApps,
  initializeApp
} from "firebase-admin/app";

import { getAuth } from "firebase-admin/auth";
import { GoogleAuth } from "google-auth-library";

let credentials;
let sheetsAuth;

export function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

export function responseHeaders(res) {
  res.setHeader("Cache-Control", "private, no-store");
  res.setHeader("Vary", "Authorization");
  res.setHeader("X-Content-Type-Options", "nosniff");
}

export function sendError(res, error) {
  const status =
    Number.isInteger(error?.status) &&
    error.status >= 400 &&
    error.status <= 599
      ? error.status
      : 500;

  console.error("Request failed:", {
    status,
    code: error?.code || "none",
    errorType: error?.name || "unknown"
  });

  return res.status(status).json({
    message:
      status === 500
        ? "Server request failed. Check Vercel runtime logs."
        : error.message
  });
}

function getCredentials() {
  if (credentials) {
    return credentials;
  }

  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  if (!raw || !raw.trim()) {
    throw httpError(
      503,
      "Server credentials are not configured."
    );
  }

  let parsed;

  try {
    parsed = JSON.parse(raw);
  } catch {
    throw httpError(
      503,
      "Server credential JSON is invalid."
    );
  }

  if (
    !parsed ||
    parsed.type !== "service_account" ||
    !parsed.project_id ||
    !parsed.client_email ||
    !parsed.private_key
  ) {
    throw httpError(
      503,
      "Required service-account fields are missing."
    );
  }

  credentials = parsed;
  return credentials;
}

export function adminAuth() {
  const serviceAccount = getCredentials();

  const existingApp = getApps().find(
    app => app.name === "[DEFAULT]"
  );

  const app = existingApp || initializeApp({
    credential: cert(serviceAccount),
    projectId: serviceAccount.project_id
  });

  return getAuth(app);
}

export function bootstrapEmail() {
  const email = String(
    process.env.BOOTSTRAP_ADMIN_EMAIL || ""
  ).trim().toLowerCase();

  if (!email) {
    throw httpError(
      503,
      "Bootstrap administrator is not configured."
    );
  }

  return email;
}

export function loginEmail(loginId) {
  return (
    loginId +
    "@repeat-contact-dashboard.firebaseapp.com"
  );
}

export function userProfile(user) {
  const claims = user.customClaims || {};

  return {
    uid: user.uid,
    name: user.displayName || user.email || user.uid,

    email:
      claims.loginMethod === "password"
        ? ""
        : user.email || "",

    loginId: claims.loginId || "",
    agentId: claims.agentId || "",
    role: claims.appRole || "agent",
    loginMethod: claims.loginMethod || "",
    active: !user.disabled
  };
}

export async function requireUser(req) {
  const authorization = String(
    req.headers.authorization || ""
  );

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    throw httpError(401, "Please sign in.");
  }

  const auth = adminAuth();

  let token;
  let user;

  try {
    token = await auth.verifyIdToken(
      match[1],
      true
    );

    // Read current server-side permissions, not only
    // possibly older custom claims in the token.
    user = await auth.getUser(token.uid);

  } catch (error) {
    console.error("Authentication failed:", {
      code: error?.code || "none",
      errorType: error?.name || "unknown"
    });

    throw httpError(
      401,
      "Session could not be verified. Please sign in again."
    );
  }

  if (user.disabled) {
    throw httpError(
      403,
      "This account is inactive."
    );
  }

  const email = String(
    user.email || ""
  ).toLowerCase();

  const provider =
    token.firebase?.sign_in_provider || "";

  if (
    email === bootstrapEmail() &&
    provider === "google.com" &&
    token.email_verified === true
  ) {
    return {
      ...userProfile(user),
      role: "admin",
      loginMethod: "google",
      bootstrap: true
    };
  }

  const claims = user.customClaims || {};

  if (
    claims.appUser !== true ||
    !["admin", "agent"].includes(claims.appRole)
  ) {
    throw httpError(
      403,
      "This account has not been approved by an administrator."
    );
  }

  if (claims.loginMethod === "google") {
    if (
      provider !== "google.com" ||
      token.email_verified !== true ||
      String(token.email || "").toLowerCase() !== email
    ) {
      throw httpError(
        403,
        "Use your approved work Google account."
      );
    }

  } else if (claims.loginMethod === "password") {
    if (provider !== "password") {
      throw httpError(
        403,
        "Use your assigned Login ID and password."
      );
    }

  } else {
    throw httpError(
      403,
      "Account login method is not configured."
    );
  }

  return {
    ...userProfile(user),
    bootstrap: false
  };
}

export async function requireAdmin(req) {
  const user = await requireUser(req);

  if (user.role !== "admin") {
    throw httpError(
      403,
      "Administrator access required."
    );
  }

  return user;
}

export function requestBody(req) {
  const contentType = String(
    req.headers["content-type"] || ""
  );

  if (!contentType.includes("application/json")) {
    throw httpError(
      415,
      "JSON request required."
    );
  }

  let body = req.body;

  try {
    if (typeof body === "string") {
      body = JSON.parse(body);
    }
  } catch {
    throw httpError(400, "Invalid JSON.");
  }

  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    throw httpError(
      400,
      "Invalid request body."
    );
  }

  return body;
}

export function checkPassword(password) {
  if (
    typeof password !== "string" ||
    password.length < 12 ||
    password.length > 128 ||
    !/[a-z]/.test(password) ||
    !/[A-Z]/.test(password) ||
    !/[0-9]/.test(password) ||
    !/[^A-Za-z0-9]/.test(password)
  ) {
    throw httpError(
      400,
      "Password must be 12–128 characters and include " +
      "uppercase, lowercase, a number and a symbol."
    );
  }
}

export async function readReport() {
  const spreadsheetId = String(
    process.env.REPORT_SPREADSHEET_ID || ""
  ).trim();

  const tab = String(
    process.env.REPORT_TAB || "Repeated_Users"
  ).trim();

  if (!/^[A-Za-z0-9_-]+$/.test(spreadsheetId)) {
    throw httpError(
      503,
      "REPORT_SPREADSHEET_ID must contain the ID only."
    );
  }

  if (!sheetsAuth) {
    sheetsAuth = new GoogleAuth({
      credentials: getCredentials(),
      scopes: [
        "https://www.googleapis.com/auth/spreadsheets.readonly"
      ]
    });
  }

  const escapedTab = tab.replace(/'/g, "''");
  const range = `'${escapedTab}'!A1:M5001`;

  const url =
    "https://sheets.googleapis.com/v4/spreadsheets/" +
    encodeURIComponent(spreadsheetId) +
    "/values/" +
    encodeURIComponent(range);

  try {
    const client = await sheetsAuth.getClient();

    const result = await client.request({
      url,
      method: "GET",
      params: {
        valueRenderOption: "FORMATTED_VALUE",
        majorDimension: "ROWS"
      },
      timeout: 15000
    });

    return result.data.values || [];

  } catch (error) {
    console.error("Report read failed:", {
      status: error.response?.status || null,
      code: error?.code || "none"
    });

    throw httpError(
      502,
      "Cannot read report. Check Sheets API, " +
      "spreadsheet ID, tab and Viewer access."
    );
  }
}
