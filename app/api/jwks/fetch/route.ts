import { fetchJwksFromUrl } from "@/lib/jwks/fetch-server";

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json(
      { code: "INVALID_URL", message: "Request body must be JSON with a url." },
      { status: 400 },
    );
  }

  const url =
    typeof body === "object" &&
    body !== null &&
    "url" in body &&
    typeof (body as { url: unknown }).url === "string"
      ? (body as { url: string }).url
      : "";

  const result = await fetchJwksFromUrl(url);
  if (result.code === "OK") {
    return Response.json({ code: "OK", jwksText: result.body });
  }

  const status =
    result.code === "INVALID_URL" || result.code === "BLOCKED_HOST"
      ? 400
      : 502;

  return Response.json(result, { status });
}
