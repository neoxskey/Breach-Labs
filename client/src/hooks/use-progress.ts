import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type UpdateProgressRequest } from "@shared/routes";
import { useAuth } from "./use-auth";
import { useToast } from "@/hooks/use-toast";

export function useProgress() {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const { toast } = useToast();

  const updateProgressMutation = useMutation({
    mutationFn: async (data: UpdateProgressRequest) => {
      const res = await fetch(api.progress.update.path, {
        method: api.progress.update.method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });

      if (!res.ok) throw new Error("Failed to sync progress");
      return api.progress.update.responses[200].parse(await res.json());
    },
    onSuccess: (updatedUser) => {
      // Optimistically update the user query
      queryClient.setQueryData([api.auth.me.path], updatedUser);
    },
    onError: () => {
      toast({
        title: "Sync Error",
        description: "Failed to save progress to mainframe.",
        variant: "destructive",
      });
    },
  });

  return {
    updateProgress: updateProgressMutation.mutate,
    isUpdating: updateProgressMutation.isPending,
  };
}
