import { Switch, Route, Link, useLocation } from "wouter";
import { QueryClientProvider } from "@tanstack/react-query";
import { queryClient } from "./lib/queryClient";
import { Toaster } from "@/components/ui/toaster";
import { useAuth } from "@/hooks/use-auth";
import { AuthModal } from "@/components/AuthModal";
import { useEffect, useState } from "react";
import Labs from "@/pages/Labs";
import Dashboard from "@/pages/Dashboard";
import { Loader2, Terminal, UserCircle, LayoutDashboard, Settings, LogOut } from "lucide-react";
import { CyberButton } from "@/components/CyberButton";
import { cn } from "@/lib/utils";

// Main layout component that wraps protected routes
function Layout({ children }: { children: React.ReactNode }) {
  const [location, setLocation] = useLocation();
  const { user, logout } = useAuth();
  
  const navItems = [
    { href: '/', label: 'Labs', icon: Terminal },
    { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { href: '/profile', label: 'Profile', icon: UserCircle },
    { href: '/settings', label: 'Settings', icon: Settings },
  ];

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col font-sans relative overflow-hidden">
      {/* Background Effects */}
      <div className="scanlines" />
      <div className="fixed inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-primary/5 via-background to-background pointer-events-none" />

      {/* Navbar */}
      <header className="h-16 border-b border-border bg-card/80 backdrop-blur-md sticky top-0 z-50 px-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-primary rounded flex items-center justify-center text-black font-bold font-display">
            BL
          </div>
          <span className="font-display font-bold tracking-widest text-lg hidden md:inline-block">
            BREACH<span className="text-primary">LABS</span>
          </span>
        </div>

        {/* Desktop Nav */}
        <nav className="hidden md:flex items-center gap-1">
          {navItems.map((item) => {
            const isActive = location === item.href;
            return (
              <Link key={item.href} href={item.href} className={cn(
                "px-4 py-2 rounded-md font-mono text-sm flex items-center gap-2 transition-all duration-200",
                isActive 
                  ? "bg-primary/10 text-primary shadow-[0_0_10px_rgba(34,197,94,0.2)]" 
                  : "text-muted-foreground hover:text-foreground hover:bg-white/5"
              )}>
                <item.icon className="w-4 h-4" />
                {item.label.toUpperCase()}
              </Link>
            )
          })}
        </nav>

        <div className="flex items-center gap-4">
          {user && (
            <div className="flex items-center gap-4">
              <div className="text-right hidden sm:block">
                <div className="text-xs font-mono text-primary">{user.username}</div>
                <div className="text-[10px] text-muted-foreground uppercase">{user.role} // RANK: {user.stats.rank}</div>
              </div>
              <CyberButton 
                variant="ghost" 
                size="sm" 
                onClick={() => logout()}
                className="w-10 h-10 p-0"
              >
                <LogOut className="w-4 h-4" />
              </CyberButton>
            </div>
          )}
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 relative z-10 overflow-x-hidden">
        {children}
      </main>
    </div>
  );
}

function AppRouter() {
  const { user, isLoading } = useAuth();
  const [showAuth, setShowAuth] = useState(false);

  // Show auth modal if not authenticated and finished loading
  useEffect(() => {
    if (!isLoading && !user) {
      setShowAuth(true);
    } else {
      setShowAuth(false);
    }
  }, [isLoading, user]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background text-primary">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-12 h-12 animate-spin" />
          <div className="font-mono text-sm animate-pulse">INITIALIZING SYSTEM...</div>
        </div>
      </div>
    );
  }

  // If not logged in, show Layout with just the modal opening automatically
  if (!user) {
    return (
      <div className="min-h-screen bg-background relative overflow-hidden flex items-center justify-center">
         <div className="absolute inset-0 bg-[url('https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=2070&auto=format&fit=crop')] bg-cover bg-center opacity-10" />
         <div className="scanlines" />
         <AuthModal open={true} onOpenChange={() => {}} />
      </div>
    );
  }

  return (
    <Layout>
      <Switch>
        <Route path="/" component={Labs} />
        <Route path="/dashboard" component={Dashboard} />
        <Route path="/profile" component={Dashboard} /> {/* Reusing Dashboard for profile MVP */}
        <Route path="/settings">
          <div className="p-12 text-center text-muted-foreground font-mono">
            SYSTEM SETTINGS LOCKED BY ADMINISTRATOR
          </div>
        </Route>
        <Route>
          <div className="flex flex-col items-center justify-center h-[60vh] text-center">
            <h1 className="text-6xl font-display font-bold text-primary/50">404</h1>
            <p className="font-mono text-muted-foreground mt-4">SECTOR NOT FOUND</p>
          </div>
        </Route>
      </Switch>
    </Layout>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Toaster />
      <AppRouter />
    </QueryClientProvider>
  );
}

export default App;
