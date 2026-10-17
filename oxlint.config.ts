import { library } from "@stll/oxlint-config";
import {
  portableSafetyPluginSpecifiers,
  portableSafetyRules,
} from "@stll/oxlint-plugin";

export default library({
  // Generated scanner/build caches and Turbo's task cache contain no source.
  ignorePatterns: ["**/.cache/**", "**/.turbo/**"],
  // Additive scanner safety checks; coverage is measured by tooling-adoption.test.ts.
  jsPlugins: [...portableSafetyPluginSpecifiers, "eslint-plugin-sonarjs"],
  rules: {
    ...portableSafetyRules,
    "sonarjs/code-eval": "error",
    "sonarjs/confidential-information-logging": "error",
    "sonarjs/no-hardcoded-secrets": "error",
    "sonarjs/no-identical-conditions": "error",
    "sonarjs/no-identical-functions": "error",
    "sonarjs/no-inverted-boolean-check": "error",
    "sonarjs/no-unthrown-error": "error",
    "sonarjs/slow-regex": "error",
    "sonarjs/stateful-regex": "error",
  },
});
