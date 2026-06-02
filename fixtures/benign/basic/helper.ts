import { readFileSync, writeFileSync } from "node:fs";

const inputPath = process.argv.at(2);
const outputPath = process.argv.at(3);

if (inputPath === undefined || outputPath === undefined) {
  throw new Error("Expected input and output paths");
}

const content = readFileSync(inputPath, "utf8");
const summary = content
  .split(/\r?\n/u)
  .filter((line) => line.startsWith("#"))
  .join("\n");

writeFileSync(outputPath, `${summary}\n`);
