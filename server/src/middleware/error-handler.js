// Centralized error handler.
// Never exposes stack traces to clients; logs them server-side only.
export default function errorHandler(err, _req, res, _next) {
  const isProduction = process.env.NODE_ENV === "production";

  // CORS errors surface as Errors thrown by the cors middleware.
  if (err.message && err.message.startsWith("CORS:")) {
    return res.status(403).json({
      success: false,
      error: {
        code: "CORS_DENIED",
        message: "Origin not permitted",
      },
    });
  }

  const message = isProduction
    ? "Internal server error"
    : (err.message || "Internal server error");

  // Log the full detail for debugging; never send it to the client.
  console.error("[error-handler]", err);

  res.status(err.status || 500).json({
    success: false,
    error: {
      code: err.code || "INTERNAL_ERROR",
      message,
    },
  });
}