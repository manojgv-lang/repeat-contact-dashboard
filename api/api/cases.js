import { createHash } from "node:crypto";

import {
  responseHeaders,
  requireAdmin,
  readReport,
  httpError,
  sendError
} from "../lib/server.js";

export default async function handler(req, res) {
  responseHeaders(res);

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");

    return res.status(405).json({
      message: "Method not allowed."
    });
  }

  try {
    // Authorise before reading any customer information.
    await requireAdmin(req);

    const values = await readReport();

    if (!values.length) {
      throw httpError(502, "The configured report tab is empty.");
    }

    const headings = values[0].map(value =>
      String(value || "").trim()
    );

    function column(name) {
      const index = headings.indexOf(name);

      if (index < 0) {
        throw httpError(
          502,
          "Expected report column is missing: " + name
        );
      }

      return index;
    }

    const fields = {
      date: column("Reporting Date — IST"),
      weekday: column("Weekday"),
      channel: column("Channel"),
      identity: column("Customer Phone / Email"),
      name: column("Customer Name"),
      count: column("Contacts on Reporting Date"),
      first: column("First Contact — IST"),
      last: column("Last Contact — IST"),

      disposition: column(
        "Latest Disposition / L1 → L2 → L3"
      ),

      owner: column(
        "Form Submitter / Ticket Owner"
      ),

      modified: column(
        "Form Time — IST / Ticket Modified — API Raw"
      ),

      ticket: column("Marvin Ticket"),
      handler: column("Case handler")
    };

    const seen = new Set();
    const cases = [];

    values.slice(1).forEach(row => {
      const date = String(row[fields.date] || "").trim();

      const channel = String(
        row[fields.channel] || ""
      ).trim().toUpperCase();

      const identity = String(
        row[fields.identity] || ""
      ).trim();

      if (
        !date ||
        !identity ||
        !["CALL", "EMAIL", "CHAT"].includes(channel)
      ) return;

      const key = JSON.stringify([
        date,
        channel,
        identity.toLowerCase()
      ]);

      if (seen.has(key)) {
        throw httpError(
          502,
          "Duplicate date/channel/customer keys exist in the report. " +
          "Resolve them before live case management."
        );
      }

      seen.add(key);

      const count = Number(
        String(row[fields.count] || "0").replace(/,/g, "")
      );

      cases.push({
        id: createHash("sha256")
          .update(key)
          .digest("hex")
          .slice(0, 32),

        date,
        weekday: row[fields.weekday] || "",
        channel,
        identity,
        customer: row[fields.name] || "",
        count: Number.isFinite(count) ? count : 0,
        first: row[fields.first] || "",
        last: row[fields.last] || "",
        disposition: row[fields.disposition] || "",
        owner: row[fields.owner] || "",
        modified: row[fields.modified] || "",
        ticket: row[fields.ticket] || "",
        handler: row[fields.handler] || ""
      });
    });

    return res.status(200).json({
      cases,
      fetchedAt: new Date().toISOString(),
      readOnly: true,

      warning:
        "Times and classifications are copied from the report. " +
        "Missing first-contact times remain missing. " +
        "Workflow status and remarks are not connected. " +
        "A fetch timestamp does not prove source completeness.",

      possiblyTruncated: values.length >= 5001
    });

  } catch (error) {
    return sendError(res, error);
  }
}
