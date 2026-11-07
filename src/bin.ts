#!/usr/bin/env node
import { ArisError } from "./client.js";
import { main } from "./cli.js";

main(process.argv.slice(2)).then(
  (code) => {
    // -1: the MCP server keeps running on stdio.
    if (code >= 0) process.exitCode = code;
  },
  (error) => {
    console.error(error instanceof ArisError ? error.message : error);
    process.exitCode = 2;
  },
);
