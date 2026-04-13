import type { AppRoute } from "../routes";

export type FeatureStatus = "idle" | "loading" | "ready" | "error";

export type FeatureState = {
  route: AppRoute;
  status: FeatureStatus;
  lastErrorCode?: string;
};

export function initializeFeatureStates(): Record<AppRoute, FeatureState> {
  return {
    vault: { route: "vault", status: "idle" },
    ingest: { route: "ingest", status: "idle" },
    search: { route: "search", status: "idle" },
    document: { route: "document", status: "idle" },
    related: { route: "related", status: "idle" },
    ask: { route: "ask", status: "idle" },
    export: { route: "export", status: "idle" },
    verify: { route: "verify", status: "idle" },
    events: { route: "events", status: "idle" },
    settings: { route: "settings", status: "idle" },
    lineage: { route: "lineage", status: "idle" }
  };
}
