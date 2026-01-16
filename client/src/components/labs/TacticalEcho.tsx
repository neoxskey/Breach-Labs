import { motion, AnimatePresence } from "framer-motion";
import { Terminal, ArrowRight, Shield, Zap, Database, Globe, Lock } from "lucide-react";

interface TacticalEchoProps {
  isOpen: boolean;
  onClose: () => void;
  payload: string;
  response: string;
  vulnerabilityType: string;
}

export function TacticalEcho({ isOpen, onClose, payload, response, vulnerabilityType }: TacticalEchoProps) {
  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-[100] flex items-center justify-center bg-black/90 backdrop-blur-xl p-4"
        >
          <div className="w-full max-w-4xl bg-black border border-primary/30 rounded-lg overflow-hidden shadow-[0_0_50px_rgba(34,197,94,0.1)]">
            {/* Header */}
            <div className="bg-primary/10 border-b border-primary/20 p-4 flex justify-between items-center">
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                <h2 className="font-display tracking-widest text-primary uppercase text-sm">Tactical Packet Echo // INTERCEPT_LIVE</h2>
              </div>
              <button 
                onClick={onClose}
                className="text-primary/50 hover:text-primary transition-colors font-mono text-xs uppercase"
              >
                [ Close Session ]
              </button>
            </div>

            <div className="p-8 grid grid-cols-1 lg:grid-cols-3 gap-8 relative">
              {/* Visual Stream Animation */}
              <div className="lg:col-span-3 h-24 flex items-center justify-center relative border-y border-white/5 bg-white/[0.02]">
                <div className="flex items-center gap-20 relative z-10 w-full px-12">
                  <motion.div 
                    initial={{ x: -20, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    className="flex flex-col items-center gap-2"
                  >
                    <div className="w-12 h-12 rounded bg-primary/20 border border-primary/50 flex items-center justify-center">
                      <Terminal className="text-primary w-6 h-6" />
                    </div>
                    <span className="text-[10px] font-mono text-primary uppercase">Origin</span>
                  </motion.div>

                  <div className="flex-1 h-[2px] bg-primary/10 relative overflow-hidden">
                    <motion.div
                      initial={{ left: "-100%" }}
                      animate={{ left: "100%" }}
                      transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                      className="absolute top-0 w-24 h-full bg-gradient-to-r from-transparent via-primary/50 to-transparent shadow-[0_0_10px_rgba(34,197,94,0.5)]"
                    />
                  </div>

                  <motion.div 
                    initial={{ scale: 0.8, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    className="flex flex-col items-center gap-2"
                  >
                    <div className="w-14 h-14 rounded-full bg-red-500/20 border border-red-500/50 flex items-center justify-center animate-pulse">
                      <Shield className="text-red-500 w-8 h-8" />
                    </div>
                    <span className="text-[10px] font-mono text-red-500 uppercase">Target</span>
                  </motion.div>

                  <div className="flex-1 h-[2px] bg-primary/10 relative overflow-hidden rotate-180">
                    <motion.div
                      initial={{ left: "-100%" }}
                      animate={{ left: "100%" }}
                      transition={{ duration: 1.5, repeat: Infinity, ease: "linear", delay: 0.75 }}
                      className="absolute top-0 w-24 h-full bg-gradient-to-r from-transparent via-primary/50 to-transparent"
                    />
                  </div>

                  <motion.div 
                    initial={{ x: 20, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    className="flex flex-col items-center gap-2"
                  >
                    <div className="w-12 h-12 rounded bg-primary/20 border border-primary/50 flex items-center justify-center">
                      <Database className="text-primary w-6 h-6" />
                    </div>
                    <span className="text-[10px] font-mono text-primary uppercase">Result</span>
                  </motion.div>
                </div>
              </div>

              {/* Data Details */}
              <div className="space-y-4">
                <div className="flex items-center gap-2 text-primary font-mono text-xs uppercase tracking-tighter opacity-70">
                  <ArrowRight className="w-3 h-3" /> Injected Payload
                </div>
                <div className="p-4 bg-primary/5 border border-primary/20 rounded font-mono text-xs text-primary/80 break-all leading-relaxed">
                  {payload}
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex items-center gap-2 text-red-500 font-mono text-xs uppercase tracking-tighter opacity-70">
                  <Zap className="w-3 h-3" /> Impact Vector
                </div>
                <div className="p-4 bg-red-500/5 border border-red-500/20 rounded font-mono text-xs text-red-400">
                  <div className="uppercase font-bold mb-1 underline decoration-red-500/30">{vulnerabilityType}</div>
                  Successful bypass detected. The server processed the unsanitized input directly into the logic flow.
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex items-center gap-2 text-primary font-mono text-xs uppercase tracking-tighter opacity-70">
                  <Globe className="w-3 h-3" /> Leaked Response
                </div>
                <div className="p-4 bg-primary/5 border border-primary/20 rounded font-mono text-xs text-primary/80 max-h-[150px] overflow-y-auto custom-scrollbar">
                  <pre className="whitespace-pre-wrap">{response}</pre>
                </div>
              </div>
            </div>

            {/* Footer Status */}
            <div className="bg-black border-t border-white/5 p-4 flex justify-between items-center">
              <div className="flex gap-4">
                <div className="text-[10px] font-mono text-muted-foreground flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-primary" /> ENCRYPTION: NONE
                </div>
                <div className="text-[10px] font-mono text-muted-foreground flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500" /> VULN: CRITICAL
                </div>
              </div>
              <div className="text-[10px] font-mono text-primary animate-pulse">
                [!] DATA_EXFILTRATION_COMPLETE
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
