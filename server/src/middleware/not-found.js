// JSON 404 handler for unknown API routes.
// Kept separate from the error handler so unknown routes are reported
// consistently without leaking internal routing details.
export default function notFound(_req, res, _next) {
  res.status(404).json({
    success: false,
    error: {
      code: "NOT_FOUND",
      message: "Route not found",
    },
  });
}