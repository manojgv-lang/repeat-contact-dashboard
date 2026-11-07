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
  if (credentials) return credentials;

  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  if (!raw) {
    throw httpError(503, "Server credentials are not configured.");
  }

  try {
    credentials = JSON.parse(raw);

    if (
      !credentials.project_id ||
      !credentials.client_email ||
      !credentials.private_key
    ) {
      throw new Error("Missing credential fields");
    }

    return credentials;

  } catch {
    throw httpError(503, "Server credential configuration is invalid.");
  }
}

function firebaseAuth() {
  const serviceAccount = getCredentials();

  const app = getApps().length
    ? getApps()[0]
    : initializeApp({
        credential: cert(serviceAccount)
      });

  return getAuth(app);
}

export async function requireAdmin(req) {
  const allowedEmail = String(
    process.env.BOOTSTRAP_ADMIN_EMAIL || ""
  ).trim().toLowerCase();

  if (!allowedEmail) {
    throw httpError(503, "Test administrator is not configured.");
  }

  const authorization = String(
    req.headers.authorization || ""
  );

  const match = authorization.match(/^Bearer\s+(\S+)$/i);

  if (!match) {
    throw httpError(401, "Sign in before requesting report data.");
  }

  let decoded;

  try {
    decoded = await firebaseAuth().verifyIdToken(
      match[1],
      true
    );

    } catch (error) {
    console.error(
      "Firebase verification failed:",
      error?.code || "unknown"
    );

    throw httpError(
      401,
      "Your session could not be verified. " +
      "Check the server authentication configuration."
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
    throw httpError(503, "Report spreadsheet is not configured.");
  }

  if (!sheetsAuth) {
    sheetsAuth = new GoogleAuth({
      credentials: getCredentials(),
      scopes: [
        "https://www.googleapis.com/auth/spreadsheets.readonly"
      ]
    });
  }

  const client = await sheetsAuth.getClient();

  const escapedTab = tab.replace(/'/g, "''");

  // Bounded read for the first test.
  const range = `'${escapedTab}'!A1:M5001`;

  const url =
    "https://sheets.googleapis.com/v4/spreadsheets/" +
    encodeURIComponent(spreadsheetId) +
    "/values/" +
    encodeURIComponent(range);

  try {
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
    console.error(
      "Report read failed:",
      error.response?.status || "unknown"
    );

    throw httpError(
      502,
      "Cannot read the report. Check the Sheets API, " +
      "spreadsheet ID, tab name and service-account Viewer access."
    );
  }
}

export function sendError(res, error) {
  const status = Number.isInteger(error.status)
    ? error.status
    : 500;

  if (status === 500) {
    console.error("Unexpected report backend error.");
  }

  return res.status(status).json({
    message: status === 500
      ? "An unexpected server error occurred."
      : error.message
  });
}
