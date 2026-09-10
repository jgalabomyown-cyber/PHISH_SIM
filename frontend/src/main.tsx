import React from "react";
import { createRoot } from "react-dom/client";
import OpsWorkspace from "./pages/OpsWorkspace";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <OpsWorkspace />
  </React.StrictMode>,
);
