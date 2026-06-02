import { library } from "@stll/oxlint-config";

export default library({
  ignorePatterns: ["**/.cache/**", "**/.turbo/**"],
  jsPlugins: ["eslint-plugin-sonarjs"],
  rules: {
    "sonarjs/code-eval": "error",
    "sonarjs/confidential-information-logging": "error",
    "sonarjs/no-hardcoded-secrets": "error",
    "sonarjs/no-identical-conditions": "error",
    "sonarjs/no-identical-functions": "error",
    "sonarjs/no-inverted-boolean-check": "error",
    "sonarjs/no-unthrown-error": "error",
    "sonarjs/slow-regex": "error",
    "sonarjs/stateful-regex": "error"
  },
});
