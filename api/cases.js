import { createHash } from "node:crypto";

import {
  responseHeaders,
  requireUser,
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
    const user = await requireUser(req);

    // Stage 1: agents must not receive all customer records.
    if (user.role !== "admin") {
      return res.status(200).json({
        cases: [],
        readOnly: true,
        fetchedAt: new Date().toISOString(),
        warning:
          "Agent assignment is not enabled yet. " +
          "No customer records are exposed to agents in Stage 1."
      });
    }

    const values = await readReport();

    if (!values.length) {
      throw httpError(
        502,
        "The configured report tab is empty."
      );
    }

    const headings = values[0].map(value =>
      String(value || "").trim()
    );

    function column(name) {
      const index = headings.indexOf(name);

      if (index < 0) {
        throw httpError(
          502,
          "Expected report column missing: " + name
        );
      }

      return index;
    }

    const names = {
      date: "Reporting Date — IST",
      weekday: "Weekday",
      channel: "Channel",
      identity: "Customer Phone / Email",
      customer: "Customer Name",
      count: "Contacts on Reporting Date",
      first: "First Contact — IST",
      last: "Last Contact — IST",
      disposition: "Latest Disposition / L1 → L2 → L3",
      owner: "Form Submitter / Ticket Owner",
      modified: "Form Time — IST / Ticket Modified — API Raw",
      ticket: "Marvin Ticket",
      handler: "Case handler"
    };

    const indexes = Object.fromEntries(
      Object.entries(names).map(([key, name]) => [
        key,
        column(name)
      ])
    );

    const seen = new Set();
    const cases = [];

    for (const sourceRow of values.slice(1)) {
      const row = Object.fromEntries(
        Object.entries(indexes).map(([key, index]) => [
          key,
          String(sourceRow[index] || "").trim()
        ])
      );

      row.channel = row.channel.toUpperCase();

      if (
        !row.date ||
        !row.identity ||
        !["CALL", "EMAIL", "CHAT"].includes(row.channel)
      ) {
        continue;
      }

      const key = JSON.stringify([
        row.date,
        row.channel,
        row.identity.toLowerCase()
      ]);

      if (seen.has(key)) {
        throw httpError(
          502,
          "Duplicate date/channel/customer keys exist in the report."
        );
      }

      seen.add(key);

      row.id = createHash("sha256")
        .update(key)
        .digest("hex")
        .slice(0, 32);

      const count = Number(
        row.count.replace(/,/g, "")
      );

      row.count = Number.isFinite(count) ? count : 0;

      cases.push(row);
    }

    return res.status(200).json({
      cases,
      readOnly: true,
      fetchedAt: new Date().toISOString(),
      possiblyTruncated: values.length >= 5001,
      warning:
        "Read-only source report. Assignment, status and remarks " +
        "are not enabled yet. Source times are copied without recalculation."
    });

  } catch (error) {
    return sendError(res, error);
  }
}
