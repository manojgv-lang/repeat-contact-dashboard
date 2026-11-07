import {
  cert,
  getApps,
  initializeApp
} from "firebase-admin/app";

import { getAuth } from "firebase-admin/auth";
import { GoogleAuth } from "google-auth-library";

let credentials;
let sheetsAuth;

export function responseHeaders(res) {
  res.setHeader("Cache-Control", "private, no-store");
  res.setHeader("Vary", "Authorization");
  res.setHeader("X-Content-Type-Options", "nosniff");
}

export function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
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
      "Server credential configuration is invalid. " +
      "The environment variable must contain valid service-account JSON."
    );
  }

  if (
    !parsed ||
    typeof parsed !== "object" ||
    parsed.type !== "service_account" ||
    typeof parsed.project_id !== "string" ||
    !parsed.project_id.trim() ||
    typeof parsed.client_email !== "string" ||
    !parsed.client_email.trim() ||
    typeof parsed.private_key !== "string" ||
    !parsed.private_key.trim()
  ) {
    throw httpError(
      503,
      "Server credential configuration is invalid. " +
      "Required service-account fields are missing."
    );
  }

  // Cache credentials only after validation succeeds.
  credentials = parsed;

  return credentials;
}

function firebaseAuth() {
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

export async function requireAdmin(req) {
  const allowedEmail = String(
    process.env.BOOTSTRAP_ADMIN_EMAIL || ""
  ).trim().toLowerCase();

  if (!allowedEmail) {
    throw httpError(
      503,
      "Test administrator is not configured."
    );
  }

  const authorization = String(
    req.headers.authorization || ""
  );

  const match = authorization.match(
    /^Bearer\s+(\S+)$/i
  );

  if (!match) {
    throw httpError(
      401,
      "Sign in before requesting report data."
    );
  }

  let decoded;
  let stage = "initialise Firebase Admin";

  try {
    const adminAuth = firebaseAuth();

    stage = "verify Firebase ID token";

    decoded = await adminAuth.verifyIdToken(
      match[1],
      true
    );
  } catch (error) {
    // Do not log tokens, private keys or credential contents.
    console.error("Firebase authentication failed:", {
      stage,
      code: error?.code || "none",
      errorType: error?.name || "unknown",
      status: error?.status || null
    });

    // Keep safe configuration errors distinct from session errors.
    if (error?.status === 503) {
      throw error;
    }

    if (stage === "initialise Firebase Admin") {
      throw httpError(
        503,
        "Firebase Admin could not initialise. " +
        "Check server credentials and the server authentication logs."
      );
    }

    throw httpError(
      401,
      "Your session could not be verified. " +
      "Check the server authentication logs."
    );
  }

  const email = String(
    decoded.email || ""
  ).trim().toLowerCase();

  const provider =
    decoded.firebase?.sign_in_provider || "";

  if (
    decoded.email_verified !== true ||
    provider !== "google.com" ||
    email !== allowedEmail
  ) {
    throw httpError(
      403,
      "This account is not authorised for the live-data test."
    );
  }

  return {
    uid: decoded.uid,
    email,
    name: decoded.name || email,
    role: "admin",
    active: true,
    agentId: ""
  };
}

export async function readReport() {
  const spreadsheetId = String(
    process.env.REPORT_SPREADSHEET_ID || ""
  ).trim();

  const tab = String(
    process.env.REPORT_TAB || "Repeated_Users"
  ).trim();

  if (!spreadsheetId || !tab) {
    throw httpError(
      503,
      "Report spreadsheet is not configured."
    );
  }

  if (!/^[A-Za-z0-9_-]+$/.test(spreadsheetId)) {
    throw httpError(
      503,
      "REPORT_SPREADSHEET_ID must contain only the spreadsheet ID, " +
      "not the full Google Sheets URL."
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
      code: error?.code || "none",
      errorType: error?.name || "unknown"
    });

    throw httpError(
      502,
      "Cannot read the report. Check the Sheets API, " +
      "spreadsheet ID, tab name and service-account Viewer access."
    );
  }
}

export function sendError(res, error) {
  const status =
    Number.isInteger(error?.status) &&
    error.status >= 400 &&
    error.status <= 599
      ? error.status
      : 500;

  if (status === 500) {
    console.error("Unexpected report backend error:", {
      code: error?.code || "none",
      errorType: error?.name || "unknown"
    });
  }

  return res.status(status).json({
    message:
      status === 500
        ? "An unexpected server error occurred."
        : error.message
  });
}
