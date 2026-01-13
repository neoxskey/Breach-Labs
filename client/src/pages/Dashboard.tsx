import { useAuth } from "@/hooks/use-auth";
import { ranks, getRank, achievements } from "@/data/labs";
import { Flame, Target, Trophy, Clock, Database, Code, Shield, Medal } from "lucide-react";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from "recharts";
import { motion } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import { api } from "@shared/routes";
import { cn } from "@/lib/utils";

export default function Dashboard() {
  const { user } = useAuth();
  const { data: leaderboard = [] } = useQuery<any[]>({
    queryKey: [api.auth.leaderboard.path],
  });
  
  if (!user) return null;

  const currentRank = getRank(user.stats.points);
  
  // Dummy data for the chart based on current stats
  const progressData = [
    { name: 'SQL', completed: 2, total: 4 },
    { name: 'XSS', completed: 1, total: 3 },
    { name: 'CSRF', completed: 0, total: 2 },
    { name: 'Auth', completed: 1, total: 4 },
    { name: 'Logic', completed: 0, total: 4 },
  ];

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatsCard 
          icon={<Trophy className="text-yellow-400" />}
          label="Current Rank"
          value={currentRank.name}
          subValue={`${user.stats.points} PTS`}
          color="border-yellow-400/20 bg-yellow-400/5"
        />
        <StatsCard 
          icon={<Target className="text-primary" />}
          label="Labs Completed"
          value={`${user.stats.completed} / ${user.stats.total}`}
          subValue={`${Math.round((user.stats.completed / user.stats.total) * 100)}% Complete`}
          color="border-primary/20 bg-primary/5"
        />
        <StatsCard 
          icon={<Flame className="text-orange-500" />}
          label="Day Streak"
          value={user.stats.streak.toString()}
          subValue="Keep it up!"
          color="border-orange-500/20 bg-orange-500/5"
        />
        <StatsCard 
          icon={<Clock className="text-blue-400" />}
          label="Last Active"
          value="Today"
          subValue={new Date(user.stats.lastActive).toLocaleTimeString()}
          color="border-blue-400/20 bg-blue-400/5"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Main Progress Chart */}
        <div className="md:col-span-2 bg-card/50 border border-border p-6 rounded-lg backdrop-blur-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10 pointer-events-none">
            <Database className="w-32 h-32" />
          </div>
          <h3 className="font-display text-lg mb-6 flex items-center gap-2">
            <Code className="w-5 h-5 text-primary" /> SKILL MATRIX
          </h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={progressData}>
                <XAxis dataKey="name" stroke="#525252" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#525252" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#09090b', border: '1px solid #27272a', borderRadius: '4px' }}
                  cursor={{ fill: '#27272a', opacity: 0.4 }}
                />
                <Bar dataKey="total" fill="#27272a" stackId="a" radius={[4, 4, 0, 0]} />
                <Bar dataKey="completed" fill="#22c55e" stackId="a" radius={[0, 0, 4, 4]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Activity / Achievements */}
        <div className="bg-card/50 border border-border p-6 rounded-lg backdrop-blur-sm space-y-8">
          <div>
            <h3 className="font-display text-lg mb-6 flex items-center gap-2">
              <Shield className="w-5 h-5 text-secondary" /> BADGES
            </h3>
            <div className="space-y-4">
              {achievements.slice(0, 3).map((ach) => (
                <motion.div 
                  key={ach.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="flex items-center gap-4 p-3 rounded bg-background/50 border border-border/50"
                >
                  <div className="text-2xl grayscale opacity-50">{ach.icon}</div>
                  <div>
                    <div className="font-bold text-sm text-muted-foreground">{ach.name}</div>
                    <div className="text-xs text-muted-foreground/50">{ach.desc}</div>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>

          <div>
            <h3 className="font-display text-lg mb-6 flex items-center gap-2">
              <Medal className="w-5 h-5 text-yellow-500" /> TOP OPERATIVES
            </h3>
            <div className="space-y-2">
              {leaderboard.map((op, idx) => (
                <div key={op.id} className="flex items-center justify-between p-2 rounded bg-background/30 text-xs border border-border/30">
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground font-mono">#{idx + 1}</span>
                    <span className={cn(op.id === user.id ? "text-primary font-bold" : "text-foreground")}>{op.username}</span>
                  </div>
                  <div className="font-mono text-primary">{op.stats.points} PTS</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatsCard({ icon, label, value, subValue, color }: any) {
  return (
    <div className={`p-4 rounded-lg border backdrop-blur-sm flex items-center gap-4 ${color}`}>
      <div className="p-3 bg-background/50 rounded-full border border-white/5">
        {icon}
      </div>
      <div>
        <div className="text-xs font-mono uppercase text-muted-foreground">{label}</div>
        <div className="text-2xl font-display font-bold tracking-wide">{value}</div>
        <div className="text-xs text-muted-foreground/70">{subValue}</div>
      </div>
    </div>
  );
}
