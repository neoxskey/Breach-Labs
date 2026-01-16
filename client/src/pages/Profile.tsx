import { useAuth } from "@/hooks/use-auth";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { User, Mail, Shield, Award, Calendar, Database, Code, Lock, Target, Zap, Network, Terminal, Search, ShieldCheck, Upload, Sliders } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import { motion } from "framer-motion";

const badgeMap: Record<string, { icon: any, label: string, color: string }> = {
  'sqli': { icon: Database, label: 'SQL Injection', color: 'text-red-500' },
  'xss': { icon: Code, label: 'XSS', color: 'text-orange-500' },
  'csrf': { icon: Shield, label: 'CSRF', color: 'text-yellow-500' },
  'auth': { icon: Lock, label: 'Authentication', color: 'text-blue-500' },
  'access': { icon: Target, label: 'Access Control', color: 'text-purple-500' },
  'business': { icon: Zap, label: 'Business Logic', color: 'text-green-500' },
  'ssrf': { icon: Network, label: 'SSRF', color: 'text-cyan-500' },
  'xxe': { icon: Terminal, label: 'XXE', color: 'text-pink-500' },
  'enumeration': { icon: Search, label: 'Enumeration', color: 'text-gray-500' },
  'broken-auth-2': { icon: ShieldCheck, label: 'Advanced Auth', color: 'text-indigo-500' },
  'file-upload': { icon: Upload, label: 'File Upload', color: 'text-emerald-500' },
  'param-tampering': { icon: Sliders, label: 'Parameter Tampering', color: 'text-sky-500' },
};

export default function Profile() {
  const { user } = useAuth();

  if (!user) return null;

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-8">
      <div className="flex flex-col gap-6">
        <div className="flex items-center gap-6">
          <div className="w-24 h-24 rounded-full bg-primary/20 border-2 border-primary/50 flex items-center justify-center">
            <User className="w-12 h-12 text-primary" />
          </div>
          <div>
            <h1 className="text-3xl font-display font-bold text-primary">{user.username}</h1>
            <p className="text-muted-foreground font-mono uppercase tracking-widest">{user.role} // RANK: {user.stats?.rank}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card className="bg-card/50 border-primary/20 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-sm font-mono uppercase tracking-wider flex items-center gap-2">
                <User className="w-4 h-4 text-primary" />
                Account Details
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between items-center border-b border-white/5 pb-2">
                <span className="text-muted-foreground text-sm flex items-center gap-2">
                  <Mail className="w-4 h-4" /> Email
                </span>
                <span className="font-mono text-sm">{user.email}</span>
              </div>
              <div className="flex justify-between items-center border-b border-white/5 pb-2">
                <span className="text-muted-foreground text-sm flex items-center gap-2">
                  <Shield className="w-4 h-4" /> Security Status
                </span>
                <Badge variant="outline" className="text-primary border-primary/30">SECURE</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-muted-foreground text-sm flex items-center gap-2">
                  <Calendar className="w-4 h-4" /> Joined
                </span>
                <span className="font-mono text-sm">{format(new Date(user.createdAt || new Date()), "PPP")}</span>
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card/50 border-primary/20 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-sm font-mono uppercase tracking-wider flex items-center gap-2">
                <Award className="w-4 h-4 text-primary" />
                Stats Overview
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between items-center border-b border-white/5 pb-2">
                <span className="text-muted-foreground text-sm">Total Labs</span>
                <span className="font-mono text-sm">{user.stats?.total}</span>
              </div>
              <div className="flex justify-between items-center border-b border-white/5 pb-2">
                <span className="text-muted-foreground text-sm">Completed</span>
                <span className="font-mono text-sm text-primary">{user.stats?.completed}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-muted-foreground text-sm">Total Points</span>
                <span className="font-mono text-sm text-primary">{user.stats?.points}</span>
              </div>
            </CardContent>
          </Card>
        </div>

        <Card className="bg-card/40 border-primary/20 backdrop-blur-sm overflow-hidden">
          <CardHeader className="border-b border-primary/10">
            <CardTitle className="text-lg font-display tracking-widest text-primary flex items-center gap-3">
              <ShieldCheck className="w-5 h-5" /> TACTICAL ACHIEVEMENTS
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6">
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-4">
              {Object.entries(badgeMap).map(([id, badge]) => {
                const isEarned = Object.keys(user.progress || {}).some(labId => labId.startsWith(id));
                return (
                  <motion.div
                    key={id}
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className={cn(
                      "flex flex-col items-center p-4 rounded-lg border text-center gap-3 transition-all",
                      isEarned 
                        ? "bg-primary/5 border-primary/30 shadow-[0_0_15px_rgba(34,197,94,0.1)]" 
                        : "bg-black/20 border-border/50 opacity-40 grayscale"
                    )}
                  >
                    <div className={cn(
                      "w-12 h-12 rounded-full flex items-center justify-center border-2",
                      isEarned ? "border-primary/50 bg-primary/10" : "border-muted/30"
                    )}>
                      <badge.icon className={cn("w-6 h-6", isEarned ? badge.color : "text-muted-foreground")} />
                    </div>
                    <div className="space-y-1">
                      <div className={cn("text-[10px] font-mono font-bold leading-tight uppercase", isEarned ? "text-primary" : "text-muted-foreground")}>
                        {badge.label}
                      </div>
                      <div className="text-[8px] font-mono text-muted-foreground uppercase opacity-50">
                        {isEarned ? 'UNLOCKED' : 'ENCRYPTED'}
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function cn(...inputs: any[]) {
  return inputs.filter(Boolean).join(' ');
}
