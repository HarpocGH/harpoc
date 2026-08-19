import { render } from "preact";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/600.css";
import "./styles/app.css";
import { App } from "./app";
import { adoptLaunchToken } from "./auth/token-store";

// Before the first render: the launch fragment is scrubbed from the address bar
// while the router is still unmounted, so `#token=…` never becomes a route.
adoptLaunchToken();

const root = document.getElementById("root");
if (root === null) throw new Error("Missing #root element");
render(<App />, root);
