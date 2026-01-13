import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { CyberButton } from './CyberButton';
import { Shield, User, Lock, Mail } from "lucide-react";
import { useAuth } from '@/hooks/use-auth';
import { motion, AnimatePresence } from 'framer-motion';

interface AuthModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function AuthModal({ open, onOpenChange }: AuthModalProps) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [formData, setFormData] = useState({ username: '', email: '', password: '' });
  const { login, register, isLoggingIn, isRegistering } = useAuth();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (mode === 'login') {
      login(
        { username: formData.username, password: formData.password },
        { onSuccess: () => onOpenChange(false) }
      );
    } else {
      register(
        formData,
        { onSuccess: () => onOpenChange(false) }
      );
    }
  };

  const isLoading = isLoggingIn || isRegistering;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-background/95 backdrop-blur-xl border-primary/30 max-w-md p-0 overflow-hidden shadow-[0_0_50px_rgba(34,197,94,0.1)]">
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary to-transparent opacity-50" />
        
        <div className="p-8">
          <DialogHeader className="mb-6">
            <div className="flex justify-center mb-4">
              <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center border border-primary/30 shadow-[0_0_15px_rgba(34,197,94,0.2)]">
                <Shield className="w-8 h-8 text-primary" />
              </div>
            </div>
            <DialogTitle className="text-center text-2xl font-display tracking-widest text-primary text-glow">
              CYBER ACADEMY PRO
            </DialogTitle>
            <DialogDescription className="text-center font-mono text-xs uppercase tracking-widest text-muted-foreground mt-2">
              {mode === 'login' ? 'Authenticate Identity' : 'Initialize New Protocol'}
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label className="font-mono text-xs uppercase text-primary/80">Username</Label>
              <div className="relative">
                <User className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input 
                  placeholder="CODENAME" 
                  className="pl-9 bg-black/20 border-primary/20 focus:border-primary/50 font-mono"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  required
                />
              </div>
            </div>

            <AnimatePresence initial={false}>
              {mode === 'register' && (
                <motion.div 
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="overflow-hidden"
                >
                  <div className="space-y-2 mb-4 pt-1">
                    <Label className="font-mono text-xs uppercase text-primary/80">Email Channel</Label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                      <Input 
                        type="email" 
                        placeholder="SECURE@MAIL.NET" 
                        className="pl-9 bg-black/20 border-primary/20 focus:border-primary/50 font-mono"
                        value={formData.email}
                        onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                        required={mode === 'register'}
                      />
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            <div className="space-y-2">
              <Label className="font-mono text-xs uppercase text-primary/80">Passkey</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input 
                  type="password" 
                  placeholder="••••••••" 
                  className="pl-9 bg-black/20 border-primary/20 focus:border-primary/50 font-mono"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  required
                />
              </div>
            </div>

            <CyberButton 
              type="submit" 
              className="w-full mt-6" 
              loading={isLoading}
            >
              {mode === 'login' ? 'ACCESS SYSTEM' : 'ESTABLISH LINK'}
            </CyberButton>
          </form>

          <div className="mt-6 text-center">
            <button 
              type="button"
              onClick={() => setMode(mode === 'login' ? 'register' : 'login')}
              className="text-xs font-mono text-muted-foreground hover:text-primary transition-colors uppercase tracking-wider"
            >
              {mode === 'login' ? 'Need Clearance? Register' : 'Have Credentials? Login'}
            </button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
