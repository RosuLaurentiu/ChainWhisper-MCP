import { ChainWhisperDomainService } from '../domain/service.js';
import { createChainWhisperDomainTools } from '../domain/tools.js';
import { createLiveChainWhisperDomainGateway } from '../domain/liveGateway.js';
import type { DomainToolDefinition } from '../domain/types.js';
import {
  createJsonMcpServer,
  type JsonMcpPrompt,
  type JsonMcpResource,
  type JsonMcpServerDefinition,
  type JsonMcpTool
} from '../server/jsonMcpServer.js';
import {
  getOrCreatePairingSecret,
  HttpJsonRpcReader,
  loadRuntimeManifest,
  CHAINWHISPER_AGENT_TOOLS_VERSION,
  type ChainWhisperRuntimeManifestV1,
  type JsonRpcReader
} from '../shared/index.js';
import { SignedDomainEnvelopeFactory } from './envelopeFactory.js';
import { ManifestExecutionPlanner } from './executionPlanner.js';

export interface PlanningServerOptions {
  manifest?: ChainWhisperRuntimeManifestV1;
  rpc?: JsonRpcReader;
  pairingSecret?: string;
  environment?: NodeJS.ProcessEnv;
  now?: () => Date;
}

export type ChainWhisperPlanningRuntime = {
  definition: JsonMcpServerDefinition;
  manifest: ChainWhisperRuntimeManifestV1;
  tools: DomainToolDefinition[];
};

const toMcpTool = (tool: DomainToolDefinition): JsonMcpTool => ({
  name: tool.name,
  title: tool.name
    .replace(/^chainwhisper_/u, '')
    .split('_')
    .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
    .join(' '),
  description: tool.description,
  inputSchema: tool.inputSchema,
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false
  },
  execute: async (input) => tool.execute(input)
});

const resourcesFor = (
  manifest: ChainWhisperRuntimeManifestV1
): JsonMcpResource[] => [
  {
    uri: 'chainwhisper://runtime/coti-mainnet',
    name: 'chainwhisper-coti-mainnet-runtime',
    title: 'ChainWhisper COTI Mainnet runtime manifest',
    description:
      'Repository-owned addresses, bytecode hashes, selectors, and verified asset references used by the keyless planner.',
    mimeType: 'application/json',
    read: () => JSON.stringify(manifest, null, 2)
  },
  {
    uri: 'chainwhisper://agent/security-boundary',
    name: 'chainwhisper-security-boundary',
    title: 'ChainWhisper MCP security boundary',
    description:
      'The planning MCP is keyless. Only the paired local signer may materialize private inputs or broadcast.',
    mimeType: 'application/json',
    read: () =>
      JSON.stringify(
        {
          planner: {
            credentials: 'never accepted',
            writes: 'never broadcast',
            output: 'HMAC-authenticated ActionEnvelopeV1'
          },
          signer: {
            location: 'local',
            confirmation: 'required before every write',
            walletAndAes: 'configured outside prompts and tool arguments'
          }
        },
        null,
        2
      )
  }
];

const prompts: JsonMcpPrompt[] = [
  {
    name: 'chainwhisper_compare_prices',
    title: 'Compare ChainWhisper price references',
    description:
      'A short workflow for comparing price references without making an unsupported liquidity claim.',
    arguments: [
      {
        name: 'pair',
        description: 'Base and quote assets, such as p.gCOTI/p.COTI.',
        required: true
      }
    ],
    render: (args) =>
      `Use chainwhisper_compare_price_references for ${args.pair ?? 'the requested pair'}. An amount is optional. Do not call a venue best unless the tool returns an executable liquidity ranking.`
  },
  {
    name: 'chainwhisper_prepare_order',
    title: 'Prepare a ChainWhisper order',
    description:
      'Validate an order request and produce a paired action envelope without signing or broadcasting.',
    arguments: [
      {
        name: 'request',
        description: 'The user-approved order terms.',
        required: true
      }
    ],
    render: (args) =>
      `Prepare this request with the matching chainwhisper_prepare_* tool: ${args.request ?? ''}\nIf the request has no explicit orderType, call chainwhisper_order_types first, explain the exact cadence, access, terms visibility, liquidity visibility, and fill style, then let the user choose. Return editable missing details when needed. Never request a private key, mnemonic, privacy key, access secret, ABI, calldata, or arbitrary contract address. The returned plan must be executed by chainwhisper-coti-signer under either one complete local confirmation or an exact active policyId.`
  }
];

export const createChainWhisperPlanningRuntime = async (
  options: PlanningServerOptions = {}
): Promise<ChainWhisperPlanningRuntime> => {
  const manifest = options.manifest ?? (await loadRuntimeManifest());
  const rpc =
    options.rpc ?? new HttpJsonRpcReader(manifest.network.rpcUrl);
  const pairingSecret =
    options.pairingSecret ??
    (await getOrCreatePairingSecret({ environment: options.environment }));
  const executionPlanner = new ManifestExecutionPlanner({
    manifest,
    rpc,
    ...(options.now ? { now: options.now } : {})
  });
  const gateway = await createLiveChainWhisperDomainGateway({
    manifest,
    rpc,
    executionPlanner: executionPlanner.plan,
    privacyBridgeStatusReader: executionPlanner.getPrivacyBridgeStatus,
    ...(options.now ? { now: () => options.now!().getTime() } : {})
  });
  const envelopeFactory = new SignedDomainEnvelopeFactory({
    manifest,
    pairingSecret,
    ...(options.now ? { now: options.now } : {})
  });
  const service = new ChainWhisperDomainService(gateway, envelopeFactory);
  const tools = createChainWhisperDomainTools(service);
  const definition: JsonMcpServerDefinition = {
    name: 'chainwhisper-mcp',
    version: CHAINWHISPER_AGENT_TOOLS_VERSION,
    instructions:
      'ChainWhisper MCP is a keyless COTI Mainnet OTC and Privacy Portal planner. Use reads before preparation. Amounts are decimal strings, never JSON numbers. Price comparison does not need an amount; rank execution only when the tool confirms executable liquidity. Privacy Portal actions must name an allowlisted pair and public-to-private or private-to-public direction. Preparation validates only repository-allowlisted contracts and selectors and returns a paired ActionEnvelopeV1. It never signs, broadcasts, sends messages, or accepts wallet credentials, privacy keys, mnemonics, access secrets, ABIs, calldata, arbitrary contracts, tokens, spenders, or admin actions. Missing optional terms are editable. Execute an envelope only through the separately registered local chainwhisper-coti-signer, using one complete local confirmation or an exact active policyId.',
    tools: tools.map(toMcpTool),
    resources: resourcesFor(manifest),
    prompts
  };
  return { definition, manifest, tools };
};

export const createChainWhisperPlanningServer = async (
  options: PlanningServerOptions = {}
) => {
  const runtime = await createChainWhisperPlanningRuntime(options);
  return createJsonMcpServer(runtime.definition);
};
