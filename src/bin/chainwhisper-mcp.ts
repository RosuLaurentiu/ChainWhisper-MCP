#!/usr/bin/env node

import { removeSignerOnlyEnvironment } from '../planner/environment.js';

removeSignerOnlyEnvironment(process.env);

const main = async (): Promise<void> => {
  const {
    connectStdioMcpServer,
    writeFatalMcpError,
  } = await import('../server/index.js');
  try {
    const { createChainWhisperPlanningServer } =
      await import('../planner/server.js');
    const server = await createChainWhisperPlanningServer();
    await connectStdioMcpServer(server);
  } catch (error: unknown) {
    writeFatalMcpError(error);
    process.exitCode = 1;
  }
};

main().catch(() => {
  process.stderr.write('[chainwhisper-mcp] chainwhisper-startup-failed\n');
  process.exitCode = 1;
});
