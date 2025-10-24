import { createError, readBody, setCookie } from "h3";
import { z } from "zod";
import { useRuntimeConfig } from "#imports";

const bodySchema = z
  .object({
    key: z.string().min(1, "API key is required"),
  })
  .strict();

export default defineEventHandler(async (event) => {
  const runtimeConfig = useRuntimeConfig(event);
  const expectedKey = runtimeConfig.admin?.apiKey;

  if (!expectedKey) {
    return { success: true, message: "Admin API key not configured" };
  }

  const parsed = bodySchema.safeParse(await readBody(event));

  if (!parsed.success) {
    throw createError({
      statusCode: 400,
      statusMessage: "Invalid request payload",
      data: parsed.error.flatten(),
    });
  }

  if (parsed.data.key !== expectedKey) {
    throw createError({
      statusCode: 401,
      statusMessage: "Invalid API key",
    });
  }

  const cookieName = runtimeConfig.public?.adminCookieName || "admin-access";

  setCookie(event, cookieName, expectedKey, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
  });

  return { success: true };
});
