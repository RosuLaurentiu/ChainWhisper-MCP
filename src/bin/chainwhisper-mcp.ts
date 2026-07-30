#!/usr/bin/env node

import {
  connectStdioMcpServer,
  writeFatalMcpError
} from '../server/index.js';
import { removeSignerOnlyEnvironment } from '../planner/environment.js';

const main = async (): Promise<void> => {
  removeSignerOnlyEnvironment(process.env);
  const { createChainWhisperPlanningServer } =
    await import('../planner/server.js');
  const server = await createChainWhisperPlanningServer();
  await connectStdioMcpServer(server);
};

main().catch((error: unknown) => {
  writeFatalMcpError(error);
  process.exitCode = 1;
});
