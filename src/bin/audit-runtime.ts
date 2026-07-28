#!/usr/bin/env node

import {
  HttpJsonRpcReader,
  auditRuntimeManifest,
  loadRuntimeManifest,
  redactError
} from '../shared/index.js';

const run = async (): Promise<void> => {
  const manifest = await loadRuntimeManifest();
  const rpcUrl = process.env.CHAINWHISPER_COTI_RPC_URL?.trim() || manifest.network.rpcUrl;
  const result = await auditRuntimeManifest(manifest, new HttpJsonRpcReader(rpcUrl));
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.ok) {
    process.exitCode = 1;
  }
};

run().catch((error: unknown) => {
  process.stderr.write(`[chainwhisper-runtime-audit] ${redactError(error)}\n`);
  process.exitCode = 1;
});
