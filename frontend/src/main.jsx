import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import "./styles/design-tokens.css";
import "./styles/globals.css";
import "./styles/theme.css";
import "./styles/socket-dashboard.css";
import "./styles/dependencies.css";
import "./styles/scan.css";
import "./styles/responsive.css";
import "./styles/settings.css";
import "./styles/block-detail.css";
import "./styles/tryit.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
