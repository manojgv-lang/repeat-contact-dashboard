import { GoogleAuth } from "google-auth-library";

import {
  requireAdmin,
  responseHeaders,
  requestBody,
  httpError,
  sendError
} from "../lib/server.js";

export default async function handler(req, res) {
  responseHeaders(res);

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");

    return res.status(405).json({
      message: "Method not allowed."
    });
  }

  try {
    const administrator = await requireAdmin(req);
    const body = requestBody(req);

    if (body.action !== "write-test") {
      throw httpError(
        400,
        "Invalid test action."
      );
    }

    const spreadsheetId = String(
      process.env.REPORT_SPREADSHEET_ID || ""
    ).trim();

    if (!/^[A-Za-z0-9_-]+$/.test(spreadsheetId)) {
      throw httpError(
        503,
        "Configure REPORT_SPREADSHEET_ID with the ID only."
      );
    }

    let credentials;

    try {
      credentials = JSON.parse(
        process.env.FIREBASE_SERVICE_ACCOUNT_JSON || ""
      );
    } catch {
      throw httpError(
        503,
        "Server credential JSON is invalid."
      );
    }

    const auth = new GoogleAuth({
      credentials,

      scopes: [
        "https://www.googleapis.com/auth/spreadsheets"
      ]
    });

    const range = "'Workflow_Test'!A1:C2";

    const url =
      "https://sheets.googleapis.com/v4/spreadsheets/" +
      encodeURIComponent(spreadsheetId) +
      "/values/" +
      encodeURIComponent(range);

    const testedAt = new Date().toISOString();

    try {
      const client = await auth.getClient();

      await client.request({
        url,
        method: "PUT",

        params: {
          valueInputOption: "RAW"
        },

        data: {
          majorDimension: "ROWS",

          values: [
            [
              "Result",
              "Tested By",
              "Tested At — UTC"
            ],
            [
              "WRITE_OK",
              administrator.email,
              testedAt
            ]
          ]
        },

        timeout: 15000
      });

    } catch (error) {
      console.error("Workflow write test failed:", {
        status: error.response?.status || null,
        code: error?.code || "none",
        errorType: error?.name || "unknown"
      });

      throw httpError(
        502,
        "Write test failed. Check that Workflow_Test exists, " +
        "the service account has Editor access, and the " +
        "Google Sheets API is enabled. See runtime logs."
      );
    }

    return res.status(200).json({
      message:
        "Sheet write test succeeded. " +
        "Check Workflow_Test cells A1:C2. " +
        "Assignment remains paused.",

      testedAt
    });

  } catch (error) {
    return sendError(res, error);
  }
}
