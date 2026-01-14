import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { CyberButton } from "@/components/CyberButton";
import { MessageSquare, Send, Bot, User, Loader2, X, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import { motion, AnimatePresence } from "framer-motion";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface ShadowOperatorProps {
  labId?: string;
  labTitle?: string;
  isOpen: boolean;
  onClose: () => void;
}

export function ShadowOperator({ labId, labTitle, isOpen, onClose }: ShadowOperatorProps) {
  const [input, setInput] = useState("");
  const [currentConversationId, setCurrentConversationId] = useState<number | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [isTyping, setIsTyping] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const { toast } = useToast();

  // Create conversation if none exists
  const createConversationMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/conversations", { 
        title: labTitle ? `Tactical Intel: ${labTitle}` : "Shadow Ops Intel" 
      });
      return res.json();
    },
    onSuccess: (data) => {
      setCurrentConversationId(data.id);
    }
  });

  useEffect(() => {
    if (isOpen && !currentConversationId) {
      createConversationMutation.mutate();
    }
  }, [isOpen, currentConversationId]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || !currentConversationId || isTyping) return;

    const userMessage: Message = { role: "user", content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput("");
    setIsTyping(true);

    try {
      const response = await fetch(`/api/conversations/${currentConversationId}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          content: labId 
            ? `Context: I am working on the lab "${labTitle}" (ID: ${labId}). ${input}`
            : input 
        }),
      });

      if (!response.ok) throw new Error("Failed to connect to Shadow Intel");

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let assistantMessage = "";

      setMessages(prev => [...prev, { role: "assistant", content: "" }]);

      while (true) {
        const { done, value } = await reader!.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split("\n");
        
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.content) {
                assistantMessage += data.content;
                setMessages(prev => {
                  const newMessages = [...prev];
                  newMessages[newMessages.length - 1].content = assistantMessage;
                  return newMessages;
                });
              }
            } catch (e) {
              // Ignore parse errors from partial chunks
            }
          }
        }
      }
    } catch (error) {
      toast({
        title: "Link Terminated",
        description: "Communication with Shadow Operator lost.",
        variant: "destructive"
      });
    } finally {
      setIsTyping(false);
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0, y: 20, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 20, scale: 0.95 }}
          className="fixed bottom-6 right-6 w-96 h-[600px] bg-card border border-primary/30 rounded-lg shadow-[0_0_30px_rgba(34,197,94,0.1)] flex flex-col z-[100] overflow-hidden backdrop-blur-md"
        >
          {/* Header */}
          <div className="p-4 border-b border-primary/20 bg-primary/5 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <Bot className="w-5 h-5 text-primary" />
                <div className="absolute -top-1 -right-1 w-2 h-2 bg-primary rounded-full animate-pulse shadow-[0_0_5px_#22c55e]" />
              </div>
              <div>
                <div className="text-xs font-mono text-primary font-bold tracking-widest">SHADOW_OPERATOR_v5</div>
                <div className="text-[10px] font-mono text-muted-foreground uppercase">{labTitle || "GLOBAL_INTEL_FEED"}</div>
              </div>
            </div>
            <button onClick={onClose} className="text-muted-foreground hover:text-primary transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Messages */}
          <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin scrollbar-thumb-primary/20">
            {messages.length === 0 && (
              <div className="h-full flex flex-col items-center justify-center text-center space-y-4 opacity-40">
                <Terminal className="w-12 h-12 text-primary" />
                <div className="font-mono text-xs uppercase tracking-widest">Awaiting Uplink...</div>
                <p className="text-[10px] max-w-[200px]">Ask for subtle hints or tactical analysis of your current target.</p>
              </div>
            )}
            {messages.map((msg, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: msg.role === "user" ? 10 : -10 }}
                animate={{ opacity: 1, x: 0 }}
                className={cn(
                  "flex gap-3",
                  msg.role === "user" ? "flex-row-reverse" : "flex-row"
                )}
              >
                <div className={cn(
                  "w-8 h-8 rounded border flex items-center justify-center shrink-0",
                  msg.role === "user" ? "border-secondary/30 bg-secondary/5 text-secondary" : "border-primary/30 bg-primary/5 text-primary"
                )}>
                  {msg.role === "user" ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
                </div>
                <div className={cn(
                  "p-3 rounded-lg text-sm font-mono leading-relaxed max-w-[80%]",
                  msg.role === "user" ? "bg-secondary/10 border border-secondary/20" : "bg-primary/10 border border-primary/20"
                )}>
                  {msg.content}
                </div>
              </motion.div>
            ))}
            {isTyping && (
              <div className="flex gap-3">
                <div className="w-8 h-8 rounded border border-primary/30 bg-primary/5 text-primary flex items-center justify-center shrink-0">
                  <Bot className="w-4 h-4" />
                </div>
                <div className="bg-primary/10 border border-primary/20 p-3 rounded-lg flex gap-1 items-center">
                  <div className="w-1.5 h-1.5 bg-primary/50 rounded-full animate-bounce" />
                  <div className="w-1.5 h-1.5 bg-primary/50 rounded-full animate-bounce [animation-delay:0.2s]" />
                  <div className="w-1.5 h-1.5 bg-primary/50 rounded-full animate-bounce [animation-delay:0.4s]" />
                </div>
              </div>
            )}
          </div>

          {/* Input */}
          <div className="p-4 border-t border-primary/20 bg-black/40">
            <div className="relative">
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSend()}
                placeholder="Request tactical intel..."
                className="w-full bg-black/40 border border-primary/30 rounded-md py-2 pl-4 pr-12 font-mono text-xs focus:outline-none focus:border-primary/60 placeholder:opacity-30"
              />
              <button
                onClick={handleSend}
                disabled={!input.trim() || isTyping}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-primary hover:text-primary-foreground disabled:opacity-30 disabled:pointer-events-none transition-all"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
