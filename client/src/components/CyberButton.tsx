import { ButtonHTMLAttributes, forwardRef } from 'react';
import { cn } from '@/lib/utils';

interface CyberButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
}

export const CyberButton = forwardRef<HTMLButtonElement, CyberButtonProps>(
  ({ className, variant = 'primary', size = 'md', loading, children, ...props }, ref) => {
    
    const variants = {
      primary: "bg-primary text-primary-foreground hover:bg-primary/90 shadow-[0_0_10px_rgba(34,197,94,0.3)] hover:shadow-[0_0_20px_rgba(34,197,94,0.5)] border-transparent",
      secondary: "bg-secondary text-secondary-foreground hover:bg-secondary/90 shadow-[0_0_10px_rgba(168,85,247,0.3)] border-transparent",
      ghost: "bg-transparent text-primary hover:bg-primary/10 border-primary/50 hover:border-primary border",
      danger: "bg-destructive text-destructive-foreground hover:bg-destructive/90 shadow-[0_0_10px_rgba(239,68,68,0.3)] border-transparent",
    };

    const sizes = {
      sm: "px-3 py-1.5 text-xs",
      md: "px-5 py-2.5 text-sm",
      lg: "px-8 py-4 text-base",
    };

    return (
      <button
        ref={ref}
        disabled={loading || props.disabled}
        className={cn(
          "relative overflow-hidden font-display font-bold tracking-wider uppercase transition-all duration-200 flex items-center justify-center gap-2",
          "disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none",
          "active:scale-95",
          // Cyberpunk corner clip
          "clip-path-polygon-[0_0,_100%_0,_100%_calc(100%_-_10px),_calc(100%_-_10px)_100%,_0_100%]", 
          variants[variant],
          sizes[size],
          className
        )}
        style={{
          clipPath: 'polygon(0 0, 100% 0, 100% calc(100% - 10px), calc(100% - 10px) 100%, 0 100%)'
        }}
        {...props}
      >
        {loading && <span className="animate-spin mr-2">⟳</span>}
        {children}
      </button>
    );
  }
);
