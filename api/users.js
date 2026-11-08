import {
  adminAuth,
  bootstrapEmail,
  loginEmail,
  userProfile,
  requireAdmin,
  responseHeaders,
  sendError,
  httpError,
  requestBody,
  checkPassword
} from "../lib/server.js";

function validEmail(email) {
  return (
    typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

export default async function handler(req, res) {
  responseHeaders(res);

  if (!["GET", "POST"].includes(req.method)) {
    res.setHeader("Allow", "GET, POST");

    return res.status(405).json({
      message: "Method not allowed."
    });
  }

  try {
    const actor = await requireAdmin(req);
    const auth = adminAuth();

    // ----------------------------------------------
    // List application users
    // ----------------------------------------------

    if (req.method === "GET") {
      const users = [];
      let pageToken;

      do {
        const page = await auth.listUsers(
          1000,
          pageToken
        );

        for (const user of page.users) {
          const isBootstrap =
            user.email?.toLowerCase() === bootstrapEmail();

          if (
            user.customClaims?.appUser !== true &&
            !isBootstrap
          ) {
            continue;
          }

          const profile = userProfile(user);

          if (isBootstrap) {
            profile.role = "admin";
            profile.loginMethod = "google";
            profile.bootstrap = true;
          }

          users.push(profile);
        }

        pageToken = page.pageToken;
      } while (pageToken);

      users.sort((a, b) =>
        a.name.localeCompare(b.name)
      );

      return res.status(200).json({ users });
    }

    const body = requestBody(req);

    // ----------------------------------------------
    // Create / approve an application user
    // ----------------------------------------------

    if (body.action === "create") {
      const name = String(
        body.name || ""
      ).trim();

      const agentId = String(
        body.agentId || ""
      ).trim();

      const role = body.role;
      const method = body.loginMethod;

      if (
        !name ||
        name.length > 100 ||
        !agentId ||
        agentId.length > 50 ||
        !["admin", "agent"].includes(role) ||
        !["google", "password"].includes(method)
      ) {
        throw httpError(
          400,
          "Enter a name, agent ID, valid role and login method."
        );
      }

      let email = "";
      let loginId = "";

      if (method === "google") {
        email = String(
          body.email || ""
        ).trim().toLowerCase();

      } else {
        const enteredEmail = String(
          body.email || ""
        ).trim().toLowerCase();

        const enteredLoginId = String(
          body.loginId || ""
        ).trim().toLowerCase();

        if (enteredEmail) {
          // Preferred: actual email + dashboard password.
          email = enteredEmail;

        } else if (enteredLoginId.includes("@")) {
          // Accept an email sent by an older form under loginId.
          email = enteredLoginId;

        } else {
          // Compatibility with the existing Login ID form.
          if (
            !/^[a-z0-9][a-z0-9._-]{2,39}$/.test(enteredLoginId)
          ) {
            throw httpError(
              400,
              "Enter the user's email address. " +
              "For a legacy Login ID, use 3–40 lowercase " +
              "letters, numbers, dots, underscores or hyphens."
            );
          }

          loginId = enteredLoginId;
          email = loginEmail(loginId);
        }

        checkPassword(body.password);
      }

      if (!validEmail(email)) {
        throw httpError(
          400,
          "Enter a valid email address."
        );
      }

      if (email === bootstrapEmail()) {
        throw httpError(
          400,
          "The bootstrap administrator already exists. " +
          "Continue using its Google sign-in."
        );
      }

      let user;
      let created = false;

      try {
        user = await auth.getUserByEmail(email);
      } catch (error) {
        if (error.code !== "auth/user-not-found") {
          throw error;
        }
      }

      if (user) {
        const providers = user.providerData || [];

        const hasPasswordProvider = providers.some(
          provider => provider.providerId === "password"
        );

        const hasOtherProvider = providers.some(
          provider => provider.providerId !== "google.com"
        );

        // Do not overwrite an existing account or password.
        // The existing Google approval flow is preserved.
        if (
          method !== "google" ||
          user.customClaims?.appUser === true ||
          hasPasswordProvider ||
          hasOtherProvider
        ) {
          throw httpError(
            409,
            "An account already exists for this email or Login ID. " +
            "Use the existing account. For an existing password " +
            "account, use Reset password instead."
          );
        }

        if (user.disabled) {
          throw httpError(
            409,
            "The existing identity is disabled. " +
            "Review it in Firebase before approval."
          );
        }

      } else {
        user = await auth.createUser({
          email,
          displayName: name,
          disabled: false,

          ...(method === "password"
            ? { password: body.password }
            : {})
        });

        created = true;
      }

      try {
        await auth.setCustomUserClaims(user.uid, {
          ...(user.customClaims || {}),
          appUser: true,
          appRole: role,
          loginMethod: method,
          loginId,
          agentId
        });

        await auth.updateUser(user.uid, {
          displayName: name
        });

      } catch (error) {
        if (created) {
          try {
            await auth.deleteUser(user.uid);
          } catch {
            console.error(
              "New-user cleanup failed. Review Firebase users."
            );
          }
        }

        throw error;
      }

      console.info("Application user approved:", {
        actorUid: actor.uid,
        targetUid: user.uid,
        role,
        loginMethod: method
      });

      return res.status(201).json({
        message:
          method === "password"
            ? loginId
              ? "Account saved. Sign in using the Login ID " +
                "and dashboard password. Share credentials privately."
              : "Account saved. Sign in using the email address " +
                "and dashboard password. Share credentials privately."
            : "Account approved. Use Continue with Google.",

        user: userProfile(
          await auth.getUser(user.uid)
        )
      });
    }

    // ----------------------------------------------
    // Activate, deactivate or reset password
    // ----------------------------------------------

    if (
      !["active", "resetPassword"].includes(body.action)
    ) {
      throw httpError(
        400,
        "Unknown action."
      );
    }

    const uid = String(body.uid || "");

    if (!uid) {
      throw httpError(
        400,
        "User ID required."
      );
    }

    const target = await auth.getUser(uid);

    if (
      target.email?.toLowerCase() === bootstrapEmail() ||
      uid === actor.uid
    ) {
      throw httpError(
        403,
        "This panel cannot change the bootstrap account " +
        "or your own account."
      );
    }

    if (target.customClaims?.appUser !== true) {
      throw httpError(
        403,
        "Not an application-managed user."
      );
    }

    if (body.action === "active") {
      if (typeof body.active !== "boolean") {
        throw httpError(
          400,
          "Active must be true or false."
        );
      }

      await auth.updateUser(uid, {
        disabled: !body.active
      });

      if (!body.active) {
        await auth.revokeRefreshTokens(uid);
      }

      console.info("Account activation changed:", {
        actorUid: actor.uid,
        targetUid: uid,
        active: body.active
      });

      return res.status(200).json({
        message:
          body.active
            ? "Account activated."
            : "Account deactivated."
      });
    }

    if (
      target.customClaims.loginMethod !== "password"
    ) {
      throw httpError(
        400,
        "Google users manage their passwords through Google."
      );
    }

    checkPassword(body.password);

    await auth.updateUser(uid, {
      password: body.password
    });

    await auth.revokeRefreshTokens(uid);

    console.info("Account password reset:", {
      actorUid: actor.uid,
      targetUid: uid
    });

    return res.status(200).json({
      message:
        "Password reset. Share the replacement privately."
    });

  } catch (originalError) {
    let error = originalError;

    if (
      !error.status &&
      [
        "auth/email-already-exists",
        "auth/uid-already-exists"
      ].includes(error.code)
    ) {
      error = httpError(
        409,
        "An account already exists for this identity."
      );
    }

    if (
      !error.status &&
      error.code === "auth/user-not-found"
    ) {
      error = httpError(
        404,
        "User not found."
      );
    }

    if (
      !error.status &&
      error.code === "auth/invalid-email"
    ) {
      error = httpError(
        400,
        "Enter a valid email address."
      );
    }

    if (
      !error.status &&
      [
        "auth/invalid-password",
        "auth/password-does-not-meet-requirements"
      ].includes(error.code)
    ) {
      error = httpError(
        400,
        "Password was rejected by Firebase. " +
        "Use at least 6 characters and check whether the " +
        "Firebase project has a stricter password policy."
      );
    }

    return sendError(res, error);
  }
}
