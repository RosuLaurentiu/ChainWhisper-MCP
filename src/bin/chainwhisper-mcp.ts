#!/usr/bin/env node

import {
  connectStdioMcpServer,
  writeFatalMcpError
} from '../server/index.js';
import { createChainWhisperPlanningServer } from '../planner/server.js';

const main = async (): Promise<void> => {
  const server = await createChainWhisperPlanningServer();
  await connectStdioMcpServer(server);
};

main().catch((error: unknown) => {
  writeFatalMcpError(error);
  process.exitCode = 1;
});
