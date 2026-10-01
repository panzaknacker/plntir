import { render } from "preact";
import { App } from "./app";
import "../../shared/theme.css";
import "./fileshare.css";

const root = document.getElementById("app");
if (root === null) throw new Error("Plntir app root is missing");
render(<App />, root);
