
import { z } from "zod";
import { insertUserSchema, loginSchema, updateProgressSchema, users } from "./schema";

export const api = {
  auth: {
    register: {
      method: "POST",
      path: "/api/register",
      input: insertUserSchema,
      responses: {
        201: z.custom<typeof users.$inferSelect>(),
        400: z.object({ message: z.string() }),
      },
    },
    login: {
      method: "POST",
      path: "/api/login",
      input: loginSchema,
      responses: {
        200: z.custom<typeof users.$inferSelect>(),
        401: z.object({ message: z.string() }),
      },
    },
    logout: {
      method: "POST",
      path: "/api/logout",
      responses: {
        200: z.object({ message: z.string() }),
      },
    },
    me: {
      method: "GET",
      path: "/api/user",
      responses: {
        200: z.custom<typeof users.$inferSelect>(),
        401: z.object({ message: z.string() }),
      },
    },
    leaderboard: {
      method: "GET",
      path: "/api/leaderboard",
      responses: {
        200: z.array(z.custom<typeof users.$inferSelect>()),
      },
    },
  },
  progress: {
    update: {
      method: "POST",
      path: "/api/progress",
      input: updateProgressSchema,
      responses: {
        200: z.custom<typeof users.$inferSelect>(),
      },
    },
  },
};
