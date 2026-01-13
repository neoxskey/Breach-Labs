
import { pgTable, text, serial, jsonb, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email").notNull(),
  password: text("password").notNull(),
  role: text("role").default("user"),
  avatar: text("avatar"),
  stats: jsonb("stats").$type<{
    completed: number;
    total: number;
    points: number;
    rank: string;
    streak: number;
    achievements: string[];
    lastActive: string;
    labTimes: Record<string, number>;
    hintsUsed: Record<string, number>;
  }>().default({
    completed: 0,
    total: 27,
    points: 0,
    rank: 'Beginner',
    streak: 0,
    achievements: [],
    lastActive: new Date().toDateString(),
    labTimes: {},
    hintsUsed: {}
  }),
  progress: jsonb("progress").$type<Record<string, { status: string; completedAt: string }>>().default({}),
  createdAt: timestamp("created_at").defaultNow(),
});

export const insertUserSchema = createInsertSchema(users);
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;

// API Schemas
export const loginSchema = z.object({
  username: z.string(),
  password: z.string(),
});

export type LoginRequest = z.infer<typeof loginSchema>;

export const updateProgressSchema = z.object({
  labId: z.string(),
  status: z.string(),
  stats: z.any(), // Full stats object update
});

export type UpdateProgressRequest = z.infer<typeof updateProgressSchema>;
