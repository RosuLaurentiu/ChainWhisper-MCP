import type { JsonMcpTool } from '../server/index.js';

import type { AutonomyDecision, AutonomyStatusV1 } from './autonomy.js';
import type { ChainWhisperSignerService } from './service.js';
import {
  createSignerTools,
  signerStatusRequiredAssets,
} from './tools.js';
import type { PublicSignerStatus } from './types.js';
import type { OpenControlPanelResult } from './localWebElicitor.js';

export type WalletSetupSignerHandlers = {
  getStatus(requiredAssets: string[]): Promise<PublicSignerStatus>;
  openControlPanel(): Promise<OpenControlPanelResult>;
  autonomyStatus(): Promise<AutonomyDecision<AutonomyStatusV1>>;
  activateFromEnvironmentFile?(): Promise<void>;
};

const CONFIGURATION_REQUIRED = {
  allowed: false,
  denial: {
    code: 'CONFIGURATION_REQUIRED',
    message:
      'Set up an Agent Wallet in local ChainWhisper Agent Control before using this tool.',
    nextAction: {
      tool: 'chainwhisper_open_control_panel',
      arguments: {},
    },
  },
} as const;

/**
 * Keeps one public MCP catalog while the signer transitions from wallet setup
 * to a configured runtime. Tool handlers are switched in memory; the MCP
 * transport and signer-owned control page stay alive.
 */
export class HotSignerToolRouter {
  readonly #setup: WalletSetupSignerHandlers;
  readonly #tools: JsonMcpTool[];
  #activeTools: Map<string, JsonMcpTool> | null = null;

  constructor(setup: WalletSetupSignerHandlers) {
    this.#setup = setup;
    const catalog = createSignerTools(
      {} as ChainWhisperSignerService,
    );
    this.#tools = catalog.map((tool) => ({
      ...tool,
      execute: (input) => this.#execute(tool.name, input),
    }));
  }

  get tools(): JsonMcpTool[] {
    return this.#tools;
  }

  activate(service: ChainWhisperSignerService): void {
    this.#activeTools = new Map(
      createSignerTools(service).map((tool) => [tool.name, tool]),
    );
  }

  get configured(): boolean {
    return this.#activeTools !== null;
  }

  async #execute(
    name: string,
    input: Record<string, unknown>,
  ): Promise<unknown> {
    if (!this.#activeTools) {
      await this.#setup.activateFromEnvironmentFile?.();
    }
    const active = this.#activeTools?.get(name);
    if (active) return active.execute(input);

    if (name === 'chainwhisper_signer_status') {
      return this.#setup.getStatus(signerStatusRequiredAssets(input));
    }
    if (name === 'chainwhisper_open_control_panel') {
      return this.#setup.openControlPanel();
    }
    if (name === 'chainwhisper_autonomy_status') {
      return this.#setup.autonomyStatus();
    }
    return CONFIGURATION_REQUIRED;
  }
}
