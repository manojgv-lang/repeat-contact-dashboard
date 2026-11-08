import {
  createHmac,
  randomUUID
} from "node:crypto";

import {
  adminAuth,
  requireUser,
  requestBody,
  responseHeaders,
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
    const user = await requireUser(req);
    const body = requestBody(req);

    const allowed = [
      "read",
      "history",
      "mode",
      "assign",
      "update"
    ];

    if (!allowed.includes(body.action)) {
      throw httpError(400, "Unknown workflow action.");
    }

    if (
      ["mode", "assign"].includes(body.action) &&
      user.role !== "admin"
    ) {
      throw httpError(403, "Administrator access required.");
    }

    const data = { ...(body.data || {}) };

    // Never trust a browser-supplied target profile.
    delete data.target;

    if (body.action === "assign") {
      const targetUid = String(data.targetUid || "");

      let target;

      try {
        target = await adminAuth().getUser(targetUid);
      } catch {
        throw httpError(400, "Selected agent was not found.");
      }

      const claims = target.customClaims || {};

      if (
        target.disabled ||
        claims.appUser !== true ||
        claims.appRole !== "agent"
      ) {
        throw httpError(
          400,
          "Select an active application agent."
        );
      }

      data.target = {
        uid: target.uid,
        name: target.displayName || claims.agentId || target.uid,
        agentId: claims.agentId || "",
        role: "agent"
      };

      delete data.targetUid;
    }

    let agents = [];

    if (body.action === "read" && user.role === "admin") {
      let pageToken;

      do {
        const page = await adminAuth().listUsers(
          1000,
          pageToken
        );

        for (const account of page.users) {
          const claims = account.customClaims || {};

          if (
            !account.disabled &&
            claims.appUser === true &&
            claims.appRole === "agent"
          ) {
            agents.push({
              uid: account.uid,
              name:
                account.displayName ||
                claims.agentId ||
                account.uid,
              agentId: claims.agentId || ""
            });
          }
        }

        pageToken = page.pageToken;

      } while (pageToken);

      agents.sort((a, b) => a.name.localeCompare(b.name));
    }

    const url = process.env.WORKFLOW_URL || "";
    const secret = process.env.WORKFLOW_SECRET || "";

    if (
      !/^https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]+\/exec$/.test(url) ||
      secret.length < 32
    ) {
      throw httpError(
        503,
        "Configure WORKFLOW_URL and WORKFLOW_SECRET."
      );
    }

    const payload = JSON.stringify({
      action: body.action,
      data,
      requestId: body.requestId || randomUUID(),

      actor: {
        uid: user.uid,
        name: user.name,
        role: user.role
      }
    });

    if (Buffer.byteLength(payload, "utf8") > 40000) {
      throw httpError(413, "Workflow request is too large.");
    }

    const timestamp = Date.now();

    const signature = createHmac("sha256", secret)
      .update(String(timestamp) + "." + payload)
      .digest("base64url");

    const controller = new AbortController();

    const timer = setTimeout(
      () => controller.abort(),
      24000
    );

    let reply;

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },

        body: JSON.stringify({
          timestamp,
          payload,
          signature
        }),

        redirect: "follow",
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error("Workflow HTTP response failed.");
      }

      reply = await response.json();

    } catch {
      throw httpError(
        502,
        "Workflow service did not return a valid response. " +
        "Check the Apps Script deployment and executions. " +
        "A timed-out write may have completed: refresh before retrying."
      );

    } finally {
      clearTimeout(timer);
    }

    if (reply.ok !== true) {
      const status = Number(reply.status);

      throw httpError(
        Number.isInteger(status) &&
        status >= 400 &&
        status <= 599
          ? status
          : 502,

        reply.message || "Workflow request failed."
      );
    }

    return res.status(200).json({
      ...reply.result,
      agents,
      user: {
        uid: user.uid,
        name: user.name,
        role: user.role
      }
    });

  } catch (error) {
    return sendError(res, error);
  }
}
