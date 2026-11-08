import {
  responseHeaders,
  requireUser,
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

    return res.status(200).json({
      user,
      assignmentMode: "paused",
      stage: 1
    });

  } catch (error) {
    return sendError(res, error);
  }
}
