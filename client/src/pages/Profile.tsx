import { useAuth } from "@/hooks/use-auth";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { User, Mail, Shield, Award, Calendar } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";

export default function Profile() {
  const { user } = useAuth();

  if (!user) return null;

  return (
    <div className="p-8 max-w-4xl mx-auto">
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
                <span className="font-mono text-sm">{format(new Date(user.createdAt), "PPP")}</span>
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
      </div>
    </div>
  );
}
