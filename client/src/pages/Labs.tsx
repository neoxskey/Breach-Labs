import { useState } from 'react';
import { topics, type Lab, type Topic } from '@/data/labs';
import { motion, AnimatePresence } from 'framer-motion';
import { cn } from '@/lib/utils';
import { CyberButton } from '@/components/CyberButton';
import { Lock, Play, CheckCircle, AlertTriangle, ChevronRight, Terminal, RefreshCcw } from 'lucide-react';
import { useAuth } from '@/hooks/use-auth';
import { useProgress } from '@/hooks/use-progress';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';

export default function Labs() {
  const [selectedTopic, setSelectedTopic] = useState<Topic>(topics[0]);
  const [activeLab, setActiveLab] = useState<Lab | null>(null);
  const { user } = useAuth();

  return (
    <div className="h-full flex flex-col md:flex-row gap-6 p-6 max-w-7xl mx-auto">
      {/* Topics Sidebar */}
      <div className="w-full md:w-64 flex-shrink-0 space-y-4">
        <h2 className="text-xl font-display text-primary mb-6 flex items-center gap-2">
          <Terminal className="w-5 h-5" /> MODULES
        </h2>
        <div className="space-y-2">
          {topics.map((topic) => (
            <button
              key={topic.id}
              onClick={() => setSelectedTopic(topic)}
              className={cn(
                "w-full p-4 rounded-lg border flex items-center gap-3 transition-all duration-200 group relative overflow-hidden",
                selectedTopic.id === topic.id 
                  ? "bg-accent/10 border-accent text-accent shadow-[0_0_15px_rgba(94,234,212,0.15)]" 
                  : "bg-card/50 border-border hover:border-primary/50 text-muted-foreground hover:text-primary"
              )}
            >
              <div className={cn(
                "p-2 rounded bg-background/50 transition-colors",
                selectedTopic.id === topic.id ? "text-accent" : topic.color
              )}>
                <topic.icon className="w-5 h-5" />
              </div>
              <div className="text-left flex-1">
                <div className="font-bold text-sm tracking-wide">{topic.name}</div>
                <div className="text-[10px] font-mono opacity-70">{topic.labs} Labs Available</div>
              </div>
              {selectedTopic.id === topic.id && (
                <motion.div layoutId="active-pill" className="absolute right-0 top-0 bottom-0 w-1 bg-accent shadow-[0_0_10px_rgba(94,234,212,0.5)]" />
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Labs Grid */}
      <div className="flex-1">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-display text-foreground tracking-wider">
            {selectedTopic.name.toUpperCase()} <span className="text-primary">//</span> LABS
          </h2>
          <div className="font-mono text-xs text-muted-foreground">
            {selectedTopic.labList.length} TARGETS AVAILABLE
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {selectedTopic.labList.length > 0 ? (
            selectedTopic.labList.map((lab) => {
              const isCompleted = user?.progress?.[lab.id]?.status === 'completed';
              return (
                <motion.div
                  key={lab.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={cn(
                    "bg-card/40 border p-6 rounded-lg backdrop-blur-sm relative group overflow-hidden transition-all hover:border-primary/50",
                    isCompleted ? "border-primary/30" : "border-border"
                  )}
                >
                  <div className="absolute top-0 right-0 p-3 opacity-20 group-hover:opacity-100 transition-opacity">
                    {isCompleted ? <CheckCircle className="text-primary w-6 h-6" /> : <Lock className="w-5 h-5" />}
                  </div>
                  
                  <div className="mb-4">
                    <span className={cn(
                      "text-[10px] font-mono px-2 py-1 rounded border uppercase tracking-widest",
                      lab.difficulty === 'apprentice' && "border-green-500/30 text-green-400 bg-green-500/5",
                      lab.difficulty === 'practitioner' && "border-yellow-500/30 text-yellow-400 bg-yellow-500/5",
                      lab.difficulty === 'expert' && "border-red-500/30 text-red-400 bg-red-500/5",
                    )}>
                      {lab.difficulty}
                    </span>
                  </div>

                  <h3 className="text-lg font-bold mb-2 group-hover:text-primary transition-colors">{lab.title}</h3>
                  <p className="text-sm text-muted-foreground mb-6 line-clamp-2">{lab.description}</p>

                  <CyberButton 
                    size="sm" 
                    className="w-full"
                    variant={isCompleted ? "secondary" : "primary"}
                    onClick={() => setActiveLab(lab)}
                  >
                    {isCompleted ? 'REPLAY MISSION' : 'START MISSION'} <Play className="w-3 h-3 ml-2" />
                  </CyberButton>
                </motion.div>
              )
            })
          ) : (
            <div className="col-span-full py-20 text-center border border-dashed border-border rounded-lg bg-card/20">
              <AlertTriangle className="w-10 h-10 text-yellow-500 mx-auto mb-4 opacity-50" />
              <p className="font-mono text-muted-foreground">NO TARGETS DETECTED IN THIS SECTOR</p>
            </div>
          )}
        </div>
      </div>

      {/* Lab Simulation Modal */}
      {activeLab && (
        <LabWorkspace lab={activeLab} open={!!activeLab} onClose={() => setActiveLab(null)} />
      )}
    </div>
  );
}

function LabWorkspace({ lab, open, onClose }: { lab: Lab, open: boolean, onClose: () => void }) {
  const [method, setMethod] = useState('GET');
  const [activeTab, setActiveWorkspaceTab] = useState<'request' | 'solution'>('request');
  const [showSolutionContent, setShowSolutionContent] = useState(false);
  const [path, setPath] = useState(lab.endpoint);
  const [headers, setHeaders] = useState('Cookie: session=xyz123\nAccept: */*');
  const [body, setBody] = useState('');
  const [response, setResponse] = useState<string | null>(null);
  const [status, setStatus] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  
  const { updateProgress } = useProgress();
  const { user } = useAuth();
  const { toast } = useToast();

  const handleSend = async () => {
    setLoading(true);
    setResponse(null);
    setStatus(null);

    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 600));

    // CHECK VULNERABILITY LOGIC
    let isSuccess = false;
    let resText = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>\n  <body>\n    <h1>Welcome</h1>\n  </body>\n</html>";
    let resStatus = 200;

    // Logic ported from original implementation
    if (lab.id === 'sqli-1' && (path.includes("' OR 1=1--") || path.includes("' OR '1'='1"))) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Dumped all users:\n- admin\n- user1\n- carlos";
    } 
    else if (lab.id === 'sqli-2' && body.includes("administrator'--")) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Logged in as administrator (Bypass)";
    }
    else if (lab.id === 'sqli-3' && path.includes("UNION SELECT NULL")) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Column count discovered: 3";
    }
    else if (lab.id === 'sqli-4' && path.includes("UNION SELECT") && (path.includes("users") || path.includes("username"))) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Credentials found:\nadmin:p4ssw0rd\ncarlos:secret";
    }
    else if (lab.id === 'xss-1' && path.includes('<script>')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] XSS Payload Reflected:\n<script>alert(1)</script>";
    }
    else if (lab.id === 'xss-2' && body.includes('<script>')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Stored XSS successful. Payload saved to database.";
    }
    else if (lab.id === 'xss-3' && path.includes('"><script>')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] DOM XSS triggered. Script executed in client context.";
    }
    else if (lab.id === 'csrf-1' && (body.includes('email=') || path.includes('email='))) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Email change request processed. Victim email updated via CSRF.";
    }
    else if (lab.id === 'csrf-2' && method === 'GET' && path.includes('email=')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] CSRF via GET successful. Protection bypassed.";
    }
    else if (lab.id === 'auth-1' && (path.includes('carlos') || body.includes('carlos'))) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Valid username enumerated: carlos (Error: Incorrect password)";
    }
    else if (lab.id === 'auth-2' && body.includes('username=carlos')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Password reset for carlos successful.";
    }
    else if (lab.id === 'auth-3' && path.includes('/my-account')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] 2FA bypassed. Access to /my-account granted.";
    }
    else if (lab.id === 'auth-4' && (body.includes('stay-logged-in') || path.includes('cookie'))) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Weak cookie cracked. Access as administrator granted.";
    }
    else if (lab.id === 'access-1' && path.includes('administrator-panel')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Unprotected admin panel accessed.";
    }
    else if (lab.id === 'access-2' && (body.includes('roleid=2') || path.includes('roleid=2'))) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Role escalation to admin (roleid=2) successful.";
    }
    else if (lab.id === 'access-3' && path.includes('id=carlos')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] IDOR successful. Accessing carlos's private data.";
    }
    else if (lab.id === 'access-4' && (path.includes('confirm') || body.includes('confirm'))) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Multi-step bypass successful. Operation confirmed without validation.";
    }
    else if (lab.id === 'business-1' && (body.includes('price=0') || path.includes('price=0'))) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Price manipulation successful. Item bought for $0.";
    }
    else if (lab.id === 'business-2' && (body.includes('quantity=-') || path.includes('quantity=-'))) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Negative quantity logic flaw exploited.";
    }
    else if (lab.id === 'business-3' && body.includes('@dontwannacry.com')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Email validation bypassed. Admin domain accepted.";
    }
    else if (lab.id === 'business-4' && body.includes('username=administrator')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Parameter injection successful. Admin settings modified.";
    }
    else if (lab.id === 'ssrf-1' && path.includes('localhost')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] SSRF to localhost successful. Internal admin panel accessed.";
    }
    else if (lab.id === 'ssrf-2' && path.includes('192.168.0')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Internal network scan successful via SSRF.";
    }
    else if (lab.id === 'ssrf-3' && (path.includes('127.1') || path.includes('127.0.0.1'))) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] SSRF filter bypass successful.";
    }
    else if (lab.id === 'xxe-1' && body.includes('<!ENTITY') && body.includes('/etc/passwd')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] XXE File Disclosure:\nroot:x:0:0:root:/root:/bin/bash";
    }
    else if (lab.id === 'xxe-2' && body.includes('169.254.169.254')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] XXE to SSRF successful. Cloud metadata accessed.";
    }
    else if (lab.id === 'xxe-3' && body.includes('<!ENTITY') && body.includes('http://')) {
      isSuccess = true;
      resText = "HTTP/1.1 200 OK\n\n[SUCCESS] Blind XXE triggered. Out-of-band request sent.";
    }
    // Add default fail states if not specific
    else {
       resText = `HTTP/1.1 200 OK\nContent-Type: text/html\n\nRequest processed for ${path}`;
    }

    setResponse(resText);
    setStatus(resStatus);
    setLoading(false);

    if (isSuccess) {
      toast({
        title: "VULNERABILITY EXPLOITED",
        description: `Target ${lab.title} compromised successfully.`,
        className: "border-primary text-primary bg-primary/10",
      });

      // Update backend if not already completed
      if (user?.progress?.[lab.id]?.status !== 'completed') {
        updateProgress({
          labId: lab.id,
          status: 'completed',
          stats: {
            ...user?.stats,
            completed: (user?.stats?.completed || 0) + 1,
            points: (user?.stats?.points || 0) + (lab.difficulty === 'apprentice' ? 10 : lab.difficulty === 'practitioner' ? 30 : 50)
          }
        });
      }
    }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-[95vw] w-full h-[90vh] p-0 gap-0 bg-background border-border overflow-hidden flex flex-col">
        {/* Header */}
        <div className="h-14 border-b bg-card flex items-center justify-between px-6 shrink-0">
          <div className="flex items-center gap-3">
            <div className={`w-2 h-2 rounded-full ${user?.progress?.[lab.id]?.status === 'completed' ? 'bg-green-500 shadow-[0_0_10px_lime]' : 'bg-red-500 animate-pulse'}`} />
            <span className="font-display font-bold tracking-wider text-lg">{lab.title}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-muted-foreground">Target: {lab.vulnerability}</span>
          </div>
        </div>

        {/* Workspace */}
        <div className="flex flex-1 overflow-hidden">
          {/* Sidebar - Instructions */}
          <div className="w-1/3 border-r bg-card/30 p-6 overflow-y-auto space-y-6">
            <div className="flex p-1 bg-background/50 rounded-lg border border-border/50 mb-4">
              <button 
                onClick={() => setActiveWorkspaceTab('request')}
                className={cn(
                  "flex-1 py-1.5 text-[10px] font-mono uppercase tracking-wider rounded transition-all",
                  activeTab === 'request' ? "bg-primary/20 text-primary shadow-sm" : "text-muted-foreground hover:text-primary"
                )}
              >
                Mission
              </button>
              <button 
                onClick={() => setActiveWorkspaceTab('solution')}
                className={cn(
                  "flex-1 py-1.5 text-[10px] font-mono uppercase tracking-wider rounded transition-all",
                  activeTab === 'solution' ? "bg-accent/20 text-accent shadow-sm" : "text-muted-foreground hover:text-accent"
                )}
              >
                Solution
              </button>
            </div>

            <AnimatePresence mode="wait">
              {activeTab === 'request' ? (
                <motion.div
                  key="mission"
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -10 }}
                  className="space-y-6"
                >
                  <div>
                    <h3 className="text-sm font-mono text-primary mb-2 uppercase tracking-wider">Mission Briefing</h3>
                    <p className="text-sm text-muted-foreground leading-relaxed">{lab.description}</p>
                  </div>
                  
                  <div>
                    <h3 className="text-sm font-mono text-primary mb-2 uppercase tracking-wider">Objective</h3>
                    <div className="bg-primary/5 border border-primary/20 p-4 rounded text-sm">
                      {lab.objective}
                    </div>
                  </div>

                  <div>
                    <h3 className="text-sm font-mono text-accent mb-2 uppercase tracking-wider">Intelligence</h3>
                    <ul className="space-y-2">
                      {lab.hints.map((hint, i) => (
                        <li key={i} className="text-xs font-mono text-muted-foreground flex items-start gap-2">
                          <span className="text-accent shrink-0">[{i+1}]</span> {hint}
                        </li>
                      ))}
                    </ul>
                  </div>
                </motion.div>
              ) : (
                <motion.div
                  key="solution"
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 10 }}
                  className="space-y-6"
                >
                  {!showSolutionContent ? (
                    <div className="space-y-6">
                      <div className="p-6 rounded-lg border border-yellow-500/30 bg-yellow-500/5 text-center space-y-4">
                        <AlertTriangle className="w-10 h-10 text-yellow-500 mx-auto opacity-50" />
                        <p className="text-sm font-mono text-yellow-500">
                          WARNING: Accessing the solution will decrease your tactical performance rating for this mission.
                        </p>
                        <CyberButton 
                          variant="secondary" 
                          size="sm" 
                          onClick={() => setShowSolutionContent(true)}
                          className="w-full border-yellow-500/50 text-yellow-500 hover:bg-yellow-500/10"
                        >
                          DECRYPT SOLUTION
                        </CyberButton>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-6">
                      <div>
                        <h3 className="text-sm font-mono text-accent mb-2 uppercase tracking-wider">Decrypted Solution</h3>
                        <div className="bg-accent/5 border border-accent/20 p-4 rounded text-sm text-muted-foreground leading-relaxed italic">
                          {lab.solution || "No solution provided for this target. Rely on your intelligence feed."}
                        </div>
                      </div>
                      <div className="p-4 rounded border border-yellow-500/20 bg-yellow-500/5">
                        <p className="text-[10px] font-mono text-yellow-500/70 uppercase">
                          TACTICAL RATING DEGRADED // DATA ACCESSED
                        </p>
                      </div>
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Main Area - Request Builder */}
          <div className="flex-1 flex flex-col bg-background relative">
            <div className="p-4 border-b bg-card/50 space-y-4">
              <div className="flex gap-2">
                <select 
                  className="bg-card border border-border rounded px-3 py-2 font-mono text-sm focus:border-primary outline-none"
                  value={method}
                  onChange={(e) => setMethod(e.target.value)}
                >
                  <option>GET</option>
                  <option>POST</option>
                  <option>PUT</option>
                  <option>DELETE</option>
                </select>
                <Input 
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  className="font-mono text-sm bg-black/20"
                />
                <CyberButton onClick={handleSend} loading={loading} className="w-32">
                  SEND <Play className="w-3 h-3 ml-2" />
                </CyberButton>
              </div>
            </div>

            <div className="flex-1 flex flex-col md:flex-row divide-y md:divide-y-0 md:divide-x overflow-hidden">
              {/* Request Panel */}
              <div className="flex-1 flex flex-col p-4 gap-4 overflow-y-auto">
                <div className="flex-1 flex flex-col gap-2">
                  <label className="text-xs font-mono uppercase text-muted-foreground">Request Headers</label>
                  <Textarea 
                    value={headers}
                    onChange={(e) => setHeaders(e.target.value)}
                    className="font-mono text-xs flex-1 bg-black/20 resize-none border-border/50 focus:border-primary/50"
                  />
                </div>
                <div className="flex-1 flex flex-col gap-2">
                  <label className="text-xs font-mono uppercase text-muted-foreground">Request Body</label>
                  <Textarea 
                    value={body}
                    onChange={(e) => setBody(e.target.value)}
                    className="font-mono text-xs flex-1 bg-black/20 resize-none border-border/50 focus:border-primary/50"
                    placeholder="param=value&other=123"
                  />
                </div>
              </div>

              {/* Response Panel */}
              <div className="flex-1 p-4 bg-black/40 overflow-y-auto font-mono text-xs relative">
                <div className="absolute top-2 right-2 text-[10px] text-muted-foreground border px-2 py-0.5 rounded border-border">
                  RESPONSE
                </div>
                {response ? (
                  <pre className={cn("whitespace-pre-wrap break-all", status === 200 ? "text-green-400" : "text-red-400")}>
                    {response}
                  </pre>
                ) : (
                  <div className="h-full flex items-center justify-center text-muted-foreground/30">
                    Awaiting Response...
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
