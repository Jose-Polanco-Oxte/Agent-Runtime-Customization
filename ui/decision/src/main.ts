import { mount } from "svelte";
import App from "./App.svelte";
import { createDecisionBridge } from "./lib/bridge";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/dialog.css";

const target = document.getElementById("app");
if (!target) {
  throw new Error("Arc decision UI mount point is missing");
}

mount(App, {
  target,
  props: { bridge: createDecisionBridge() },
});
