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

    if (
      !["read", "history", "assign", "update"]
        .includes(body.action)
    ) {
      throw httpError(400, "Unknown workflow action.");
    }

    if (
      body.action === "assign" &&
      user.role !== "admin"
    ) {
      throw httpError(403, "Administrator access required.");
    }

    const data = { ...(body.data || {}) };

    // Target identity is always verified on the server.
    delete data.target;

    if (body.action === "assign") {
      let target;

      try {
        target = await adminAuth().getUser(
          String(data.targetUid || "")
        );
      } catch {
        throw httpError(400, "Selected user was not found.");
      }

      const claims = target.customClaims || {};

      if (
        target.disabled ||
        claims.appUser !== true ||
        !["admin", "agent"].includes(claims.appRole)
      ) {
        throw httpError(400, "Select an active application user.");
      }

      data.target = {
        uid: target.uid,
        name:
          target.displayName ||
          claims.agentId ||
          target.uid,
        agentId: claims.agentId || "",
        role: claims.appRole
      };

      delete data.targetUid;
    }

    const users = [];

    if (
      body.action === "read" &&
      user.role === "admin"
    ) {
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
            ["admin", "agent"].includes(claims.appRole)
          ) {
            users.push({
              uid: account.uid,
              name:
                account.displayName ||
                claims.agentId ||
                account.uid,
              agentId: claims.agentId || "",
              role: claims.appRole
            });
          }
        }

        pageToken = page.pageToken;
      } while (pageToken);

      users.sort((a, b) =>
        a.name.localeCompare(b.name)
      );
    }

    const url = process.env.WORKFLOW_URL || "";
    const secret = process.env.WORKFLOW_SECRET || "";

    if (
      !/^https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]+\/exec$/.test(url) ||
      secret.length < 32
    ) {
      throw httpError(503, "Workflow configuration is missing.");
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
      throw httpError(413, "Request is too large.");
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
        throw new Error("Workflow response failed.");
      }

      reply = await response.json();
    } catch {
      throw httpError(
        502,
        "Could not confirm the workflow response. " +
        "Refresh before retrying: a save may have completed."
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
      users,
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
