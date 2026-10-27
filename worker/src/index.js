// Text assets are served directly from the repository by Wrangler's Text rules.
import collectorScript from "../../collector/tattle-collect";
import installScript from "../../collector/install.sh";
import { createWorker } from "./runtime.js";
export { HostGate } from "./runtime.js";
export default createWorker({ collectorScript, installScript });
