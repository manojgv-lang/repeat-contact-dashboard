import {
  adminAuth,
  bootstrapEmail,
  requireAdmin,
  responseHeaders,
  sendError,
  httpError,
  requestBody
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
    const actor = await requireAdmin(req);
    const body = requestBody(req);

    const uid = String(body.uid || "").trim();

    const confirmation = String(
      body.confirmation || ""
    ).trim().toLowerCase();

    if (!uid || !confirmation) {
      throw httpError(
        400,
        "User ID and confirmation are required."
      );
    }

    const auth = adminAuth();
    const target = await auth.getUser(uid);

    const targetEmail = String(
      target.email || ""
    ).toLowerCase();

    if (
      uid === actor.uid ||
      targetEmail === bootstrapEmail()
    ) {
      throw httpError(
        403,
        "You cannot delete your own account " +
        "or the bootstrap administrator."
      );
    }

    const claims = target.customClaims || {};

    if (claims.appUser !== true) {
      throw httpError(
        403,
        "This is not an application-managed user."
      );
    }

    if (!target.disabled) {
      throw httpError(
        409,
        "Deactivate this account before deleting it."
      );
    }

    const expectedConfirmation = String(
      claims.loginMethod === "password"
        ? claims.loginId || ""
        : target.email || ""
    ).trim().toLowerCase();

    if (
      !expectedConfirmation ||
      confirmation !== expectedConfirmation
    ) {
      throw httpError(
        400,
        "Confirmation does not match the selected account."
      );
    }

    await auth.revokeRefreshTokens(uid);
    await auth.deleteUser(uid);

    console.info("Application user deleted:", {
      actorUid: actor.uid,
      targetUid: uid
    });

    return res.status(200).json({
      message:
        "User account deleted. It has been removed " +
        "from the application-user list."
    });

  } catch (originalError) {
    let error = originalError;

    if (
      !error.status &&
      error.code === "auth/user-not-found"
    ) {
      error = httpError(
        404,
        "Account no longer exists. Refresh the user list."
      );
    }

    return sendError(res, error);
  }
}
