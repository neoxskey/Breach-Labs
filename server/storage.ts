
import { db } from "./db";
import { users, type User, type InsertUser } from "@shared/schema";
import { eq } from "drizzle-orm";

export interface IStorage {
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUserStats(userId: number, stats: any, progress: any): Promise<User>;
  getTopUsers(limit: number): Promise<User[]>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }

  async updateUserStats(userId: number, stats: any, progress: any): Promise<User> {
    const [user] = await db
      .update(users)
      .set({ stats, progress })
      .where(eq(users.id, userId))
      .returning();
    return user;
  }

  async getTopUsers(limit: number): Promise<User[]> {
    // In Drizzle, we need to handle the sorting of JSONB fields if necessary, 
    // but for now we'll sort by the points field in the stats JSONB.
    // Since stats is a JSONB column, we use the ->> operator in raw SQL or similar.
    // For simplicity in this demo, let's fetch all and sort in memory or use a better schema.
    const allUsers = await db.select().from(users);
    return allUsers
      .sort((a, b) => (b.stats?.points || 0) - (a.stats?.points || 0))
      .slice(0, limit);
  }
}

export const storage = new DatabaseStorage();
