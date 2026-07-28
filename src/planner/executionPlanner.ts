import {
  decodeFunctionResult,
  encodeAbiParameters,
  parseAbi,
  parseUnits,
  toHex,
  type Hex
} from 'viem';

import { DomainInputError } from '../domain/errors.js';
import type {
  Address,
  DomainExecutionPlan,
  DomainIntent,
  DomainStatus,
  PlanStep,
  PlanPrivateArtifactGroup,
  PlanPrivateArtifactValueSource,
  ResolvedAsset
} from '../domain/types.js';
import type { JsonRpcReader } from '../shared/runtimeManifest.js';
import type {
  ChainWhisperRuntimeManifestV1,
  RuntimeContractManifestEntry
} from '../shared/runtimeManifest.js';
import {
  privacyBridgePair,
  type PrivacyBridgePairV1
} from '../shared/privacyBridge.js';
import {
  APPROVE_SELECTOR,
  PRIVATE_APPROVE_SELECTOR,
  encodeAllowlistedPlanStep,
  encodeReadCall
} from './allowlist.js';

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as Address;
const ZERO_BYTES32 = `0x${'0'.repeat(64)}`;
const EMPTY_IT_UINT256 = [['0', '0'], '0x'] as const;
const APPROVAL_GAS_CAP = 250_000n;
const PRIVATE_WRITE_GAS_CAP = 8_000_000n;
const STANDARD_GAS_CAP = 2_000_000n;
const RECURRING_GAS_CAP = 4_000_000n;
const DEFAULT_PLAN_TTL_MS = 15 * 60 * 1_000;

const FEE_ABI = parseAbi([
  'function feeAmount() view returns (uint256)',
  'function feeRecipient() view returns (address)'
]);
const EDIT_FEE_ABI = parseAbi([
  'function chargeFeeOnEdit() view returns (bool)'
]);
const DEFAULT_PARTIAL_FILL_ABI = parseAbi([
  'function defaultMinPartialFillBps() view returns (uint16)'
]);
const DIRECT_COUNTER_TRUST_ABI = parseAbi([
  'function trustedDirectCounterEscrow(address escrow) view returns (bool)'
]);
const ALLOWANCE_ABI = parseAbi([
  'function allowance(address owner,address spender) view returns (uint256)'
]);
const BRIDGE_COMMON_ABI = parseAbi([
  'function paused() view returns (bool)',
  'function isDepositEnabled() view returns (bool)',
  'function minDepositAmount() view returns (uint256)',
  'function maxDepositAmount() view returns (uint256)',
  'function minWithdrawAmount() view returns (uint256)',
  'function maxWithdrawAmount() view returns (uint256)',
  'function blacklisted(address account) view returns (bool)'
]);
const BRIDGE_NATIVE_ABI = parseAbi([
  'function privateCoti() view returns (address)',
  'function estimateDepositFee(uint256 amount) view returns (uint256 fee,uint256 cotiLastUpdated,uint256 blockTimestamp)',
  'function estimateWithdrawFee(uint256 amount) view returns (uint256 fee,uint256 cotiLastUpdated,uint256 blockTimestamp)'
]);
const BRIDGE_ERC20_ABI = parseAbi([
  'function token() view returns (address)',
  'function privateToken() view returns (address)',
  'function estimateDepositFee(uint256 amount) view returns (uint256 fee,uint256 cotiLastUpdated,uint256 tokenLastUpdated,uint256 blockTimestamp)',
  'function estimateWithdrawFee(uint256 amount) view returns (uint256 fee,uint256 cotiLastUpdated,uint256 tokenLastUpdated,uint256 blockTimestamp)'
]);
const PRIVATE_TOKEN_BRIDGE_ABI = parseAbi([
  'function publicAmountsEnabled() view returns (bool)'
]);
const WISP_BRIDGE_FEE_ABI = parseAbi([
  'function nativeCotiFee() view returns (uint256)'
]);

export type PlannerRpc = JsonRpcReader;

export interface ManifestExecutionPlannerOptions {
  manifest: ChainWhisperRuntimeManifestV1;
  rpc: PlannerRpc;
  now?: () => Date;
  ttlMs?: number;
}

type BuiltPlan = {
  contract: RuntimeContractManifestEntry;
  steps: PlanStep[];
  nativePrincipal: bigint;
  feeRequired: boolean;
  expectedResult: string;
  intentMetadata?: Record<string, string | number | boolean | null>;
};

const asAtomic = (
  value: string,
  asset: Pick<ResolvedAsset, 'symbol' | 'decimals'>
): bigint => {
  try {
    const atomic = parseUnits(value, asset.decimals);
    if (atomic <= 0n) throw new Error('non-positive');
    return atomic;
  } catch {
    throw new DomainInputError(
      `${asset.symbol} amount cannot be represented at ${asset.decimals} decimals.`,
      [],
      'invalid_input'
    );
  }
};

const asOptionalAtomic = (
  value: string | null | undefined,
  asset: Pick<ResolvedAsset, 'symbol' | 'decimals'>
): bigint => {
  if (!value) return 0n;
  try {
    const atomic = parseUnits(value, asset.decimals);
    if (atomic < 0n) throw new Error('negative');
    return atomic;
  } catch {
    throw new DomainInputError(
      `${asset.symbol} amount cannot be represented at ${asset.decimals} decimals.`,
      [],
      'invalid_input'
    );
  }
};

const assetTuple = (
  asset: ResolvedAsset,
  amount: bigint
): [number, Address, string] => [
  asset.kind === 'native' ? 0 : asset.kind === 'erc20' ? 1 : 2,
  asset.address ?? ZERO_ADDRESS,
  amount.toString()
];

const recurringAssetTuple = (
  asset: ResolvedAsset
): [number, Address] => [
  asset.kind === 'native' ? 0 : asset.kind === 'erc20' ? 1 : 2,
  asset.address ?? ZERO_ADDRESS
];

const isoToUnixSeconds = (value: string | null): string => {
  if (!value) return '0';
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || milliseconds <= 0) {
    throw new DomainInputError('The order expiry is invalid.');
  }
  return Math.floor(milliseconds / 1_000).toString();
};

const requireManifestContract = (
  manifest: ChainWhisperRuntimeManifestV1,
  name: string
): RuntimeContractManifestEntry => {
  const contract = manifest.contracts[name];
  if (!contract) {
    throw new DomainInputError(
      `The audited ${name} contract is unavailable.`,
      [],
      'unsupported'
    );
  }
  return contract;
};

const requireSelector = (
  contract: RuntimeContractManifestEntry,
  name: string
): `0x${string}` => {
  const selector = contract.selectors[name];
  if (!selector) {
    throw new DomainInputError(
      `The deployed contract does not expose the allowlisted ${name} action.`,
      [],
      'unsupported'
    );
  }
  return selector;
};

const unsupported = (message: string): never => {
  throw new DomainInputError(message, [], 'unsupported');
};

const assertUint128 = (value: bigint, label: string): void => {
  if (value > (1n << 128n) - 1n) {
    throw new DomainInputError(
      `${label} exceeds the deployed standard escrow's uint128 limit.`,
      [],
      'invalid_input'
    );
  }
};

const sumGas = (steps: readonly PlanStep[]): bigint =>
  steps.reduce(
    (total, step) =>
      total +
      BigInt(
        step.gasCap ??
          (step.kind === 'approval'
            ? APPROVAL_GAS_CAP
            : step.description.startsWith('Create recurring')
              ? RECURRING_GAS_CAP
              : STANDARD_GAS_CAP)
      ),
    0n
  );

const artifactValue = (
  id: string,
  kind: 'uint256' | 'access-secret',
  source: PlanPrivateArtifactValueSource,
  asset?: ResolvedAsset,
  allowZero = false
): PlanPrivateArtifactGroup['values'][number] => ({
  id,
  kind,
  source,
  ...(asset ? { asset } : {}),
  ...(allowZero ? { allowZero: true } : {})
});

export class ManifestExecutionPlanner {
  readonly #manifest: ChainWhisperRuntimeManifestV1;
  readonly #rpc: PlannerRpc;
  readonly #now: () => Date;
  readonly #ttlMs: number;

  constructor(options: ManifestExecutionPlannerOptions) {
    this.#manifest = options.manifest;
    this.#rpc = options.rpc;
    this.#now = options.now ?? (() => new Date());
    this.#ttlMs = options.ttlMs ?? DEFAULT_PLAN_TTL_MS;
  }

  readonly plan = async (
    intent: DomainIntent,
    status: DomainStatus
  ): Promise<DomainExecutionPlan> => {
    this.#assertReady(status);
    if (!intent.wallet) {
      throw new DomainInputError('Choose the local signer wallet.');
    }
    const touchesRecurring =
      intent.action === 'create_recurring' ||
      ('order' in intent && intent.order.kind === 'recurring');
    if (touchesRecurring && !status.registry.recurringWritesEnabled) {
      throw new DomainInputError(
        'Recurring writes are disabled until the deployed bytecode and selector audit agrees with the runtime manifest.',
        [],
        'unsupported'
      );
    }
    const built = await this.#build(intent);
    const fee =
      intent.action === 'privacy_bridge'
        ? { amount: 0n, recipient: built.contract.address as Address }
        : await this.#readFee(built.contract);
    const feeAmount = built.feeRequired ? fee.amount : 0n;
    const protocolStep = built.steps.at(-1);
    if (!protocolStep || protocolStep.kind !== 'protocol') {
      throw new DomainInputError(
        'The action did not produce an allowlisted protocol step.',
        [],
        'unsupported'
      );
    }
    protocolStep.nativeValue = (
      BigInt(protocolStep.nativeValue) + feeAmount
    ).toString();
    const simulation = await this.#simulate(intent.wallet, built.steps);
    const exactNativeValue = built.steps.reduce(
      (total, step) => total + BigInt(step.nativeValue),
      0n
    );
    if (exactNativeValue !== built.nativePrincipal + feeAmount) {
      throw new DomainInputError(
        'The planned native value does not match its principal and fee.',
        [],
        'provider_error'
      );
    }
    return {
      wallet: intent.wallet,
      registry: status.registry,
      steps: built.steps,
      fee: {
        token: 'native',
        amount: feeAmount.toString(),
        scheduleAmount: fee.amount.toString(),
        recipient: fee.recipient
      },
      exactNativeValue: exactNativeValue.toString(),
      gasCap: sumGas(built.steps).toString(),
      simulation: {
        ok: simulation.ok,
        deferredPrivateArtifacts: simulation.deferredPrivateArtifacts,
        blockNumber: simulation.blockNumber,
        expectedResult: built.expectedResult,
        warnings: simulation.warnings,
        ...(simulation.errorCode ? { errorCode: simulation.errorCode } : {})
      },
      expiresAt: new Date(this.#now().getTime() + this.#ttlMs).toISOString(),
      ...(built.intentMetadata ? { intentMetadata: built.intentMetadata } : {})
    };
  };

  #assertReady(status: DomainStatus): void {
    if (
      !status.ready ||
      status.readOnly ||
      status.registry.chainId !== this.#manifest.network.chainId ||
      status.registry.registryAddress.toLowerCase() !==
        this.#manifest.registry.address.toLowerCase()
    ) {
      throw new DomainInputError(
        'ChainWhisper writes are read-only until the live registry and bytecode audit pass.',
        [],
        'unsupported'
      );
    }
  }

  async #build(intent: DomainIntent): Promise<BuiltPlan> {
    switch (intent.action) {
      case 'create_trade':
        return this.#buildCreateTrade(intent);
      case 'create_recurring':
        return this.#buildCreateRecurring(intent);
      case 'fill':
        return this.#buildFill(intent);
      case 'order_update':
        return this.#buildOrderUpdate(intent);
      case 'counter':
        return this.#buildCounter(intent);
      case 'edit':
        return this.#buildEdit(intent);
      case 'privacy_bridge':
        return this.#buildPrivacyBridge(intent);
    }
  }

  readonly getPrivacyBridgeStatus = async (
    input: import('../domain/types.js').PrivacyBridgeStatusInput
  ): Promise<import('../domain/types.js').PrivacyBridgeStatus> => {
    const pair =
      privacyBridgePair(input.pair) ??
      unsupported('Choose one of the eight allowlisted Privacy Portal pairs.');
    const contract = requireManifestContract(this.#manifest, pair.contractName);
    if (
      contract.address.toLowerCase() !== pair.bridgeAddress.toLowerCase()
    ) {
      return unsupported('The bridge address does not match the audited pair catalog.');
    }
    const publicAsset = this.#manifestAsset(pair.publicSymbol);
    const privateAsset = this.#manifestAsset(pair.privateSymbol);
    if (
      publicAsset.decimals !== pair.decimals ||
      privateAsset.decimals !== pair.decimals ||
      privateAsset.address?.toLowerCase() !==
        pair.privateTokenAddress.toLowerCase() ||
      (pair.publicTokenAddress &&
        publicAsset.address?.toLowerCase() !==
          pair.publicTokenAddress.toLowerCase())
    ) {
      return unsupported('The verified bridge token pair does not match the runtime manifest.');
    }
    await this.#verifyBridgePair(pair, contract);
    const [paused, depositEnabled, privatePublicAmountsEnabled] = await Promise.all([
      this.#readBridgeBoolean(contract.address as Address, 'paused'),
      this.#readBridgeBoolean(contract.address as Address, 'isDepositEnabled'),
      this.#readBridge(
        pair.privateTokenAddress as Address,
        PRIVATE_TOKEN_BRIDGE_ABI,
        'publicAmountsEnabled'
      ) as Promise<boolean>
    ]);
    const blacklisted = input.wallet
      ? await this.#readBridgeBoolean(
          contract.address as Address,
          'blacklisted',
          [input.wallet]
        )
      : null;
    const amount =
      input.amount && input.direction
        ? asAtomic(input.amount, publicAsset)
        : null;
    let minAmount: bigint | null = null;
    let maxAmount: bigint | null = null;
    let quote:
      | {
          fee: bigint;
          cotiOracleTimestamp: bigint;
          tokenOracleTimestamp: bigint;
          blockTimestamp: bigint;
        }
      | null = null;
    if (input.direction) {
      const prefix =
        input.direction === 'public-to-private' ? 'Deposit' : 'Withdraw';
      [minAmount, maxAmount] = await Promise.all([
        this.#readBridgeUint(
          contract.address as Address,
          `min${prefix}Amount`
        ),
        this.#readBridgeUint(
          contract.address as Address,
          `max${prefix}Amount`
        )
      ]);
      if (amount !== null) {
        quote = await this.#readBridgeQuote(
          pair,
          contract.address as Address,
          input.direction,
          amount
        );
        if (pair.id === 'wisp') {
          const configuredFee = (await this.#readBridge(
            contract.address as Address,
            WISP_BRIDGE_FEE_ABI,
            'nativeCotiFee'
          )) as bigint;
          if (configuredFee !== quote.fee) {
            throw new DomainInputError(
              'The ChainWhisper WISP bridge fee changed while quoting.',
              [],
              'provider_error'
            );
          }
        }
      }
    }
    const warnings: string[] = [];
    if (paused) warnings.push('The bridge is paused.');
    if (input.direction === 'public-to-private' && !depositEnabled) {
      warnings.push('Deposits are disabled.');
    }
    if (blacklisted) warnings.push('The wallet is blacklisted by this bridge.');
    if (
      input.direction === 'private-to-public' &&
      !privatePublicAmountsEnabled
    ) {
      warnings.push('The private token does not currently allow public-amount bridge transfers.');
    }
    if (amount !== null && minAmount !== null && amount < minAmount) {
      warnings.push('The amount is below the bridge minimum.');
    }
    if (amount !== null && maxAmount !== null && amount > maxAmount) {
      warnings.push('The amount exceeds the bridge maximum.');
    }
    return {
      pair: pair.id,
      provider: pair.provider,
      bridge: contract.address as Address,
      publicAsset,
      privateAsset,
      ready: warnings.length === 0,
      paused,
      depositEnabled,
      privatePublicAmountsEnabled,
      blacklisted,
      direction: input.direction ?? null,
      amount: input.amount ?? null,
      amountAtomic: amount?.toString() ?? null,
      minAmountAtomic: minAmount?.toString() ?? null,
      maxAmountAtomic: maxAmount?.toString() ?? null,
      portalFeeAtomic: quote?.fee.toString() ?? null,
      cotiOracleTimestamp: quote?.cotiOracleTimestamp.toString() ?? null,
      tokenOracleTimestamp: quote?.tokenOracleTimestamp.toString() ?? null,
      blockTimestamp: quote?.blockTimestamp.toString() ?? null,
      warnings
    };
  };

  async #buildPrivacyBridge(
    intent: Extract<DomainIntent, { action: 'privacy_bridge' }>
  ): Promise<BuiltPlan> {
    if (
      !intent.wallet ||
      !intent.publicAsset ||
      !intent.privateAsset ||
      !intent.amount
    ) {
      return unsupported('The Privacy Portal plan is missing required editable terms.');
    }
    const pair =
      privacyBridgePair(intent.pair) ??
      unsupported('The Privacy Portal pair is not allowlisted.');
    const status = await this.getPrivacyBridgeStatus({
      wallet: intent.wallet,
      pair: intent.pair,
      direction: intent.direction,
      amount: intent.amount
    });
    if (!status.ready) {
      throw new DomainInputError(
        status.warnings.join(' ') || 'The selected bridge route is unavailable.',
        [],
        'unsupported'
      );
    }
    const contract = requireManifestContract(this.#manifest, pair.contractName);
    const amount = BigInt(status.amountAtomic!);
    const portalFee = BigInt(status.portalFeeAtomic!);
    const inputAsset =
      intent.direction === 'public-to-private'
        ? intent.publicAsset
        : intent.privateAsset;
    const approvals = await this.#approvalSteps(
      intent.wallet,
      inputAsset,
      contract.address as Address,
      amount,
      'intent-sell-amount',
      'privacy-bridge-amount'
    );
    const selectorName =
      intent.direction === 'public-to-private' ? 'deposit' : 'withdraw';
    const cotiTimestamp = status.cotiOracleTimestamp!;
    const tokenTimestamp = status.tokenOracleTimestamp!;
    const nativeValue =
      pair.bridgeKind === 'native'
        ? intent.direction === 'public-to-private'
          ? amount
          : 0n
        : portalFee;
    const args =
      pair.bridgeKind === 'native' &&
      intent.direction === 'public-to-private'
        ? [cotiTimestamp, tokenTimestamp]
        : [amount.toString(), cotiTimestamp, tokenTimestamp];
    const protocol: PlanStep = {
      id: `privacy-bridge-${pair.id}-${selectorName}`,
      kind: 'protocol',
      contract: contract.address as Address,
      description: `${
        intent.direction === 'public-to-private' ? 'Shield' : 'Unshield'
      } ${intent.amount} ${
        intent.direction === 'public-to-private'
          ? pair.publicSymbol
          : pair.privateSymbol
      } through the ${pair.provider === 'official-coti' ? 'official COTI' : 'ChainWhisper'} privacy bridge`,
      nativeValue: nativeValue.toString(),
      gasCap: PRIVATE_WRITE_GAS_CAP.toString(),
      encoding: {
        selector: requireSelector(contract, selectorName),
        arguments: args
      }
    };
    return {
      contract,
      steps: [...approvals, protocol],
      nativePrincipal: nativeValue,
      feeRequired: false,
      expectedResult: `${
        intent.direction === 'public-to-private' ? 'Shield' : 'Unshield'
      } exactly ${intent.amount} ${inputAsset.symbol} into ${
        intent.direction === 'public-to-private'
          ? intent.privateAsset.symbol
          : intent.publicAsset.symbol
      }.`,
      intentMetadata: {
        bridgePair: pair.id,
        bridgeProvider: pair.provider,
        bridgeContractName: pair.contractName,
        bridgeKind: pair.bridgeKind,
        bridgeDirection: intent.direction,
        amountAtomic: amount.toString(),
        portalFeeAtomic: portalFee.toString(),
        cotiOracleTimestamp: cotiTimestamp,
        tokenOracleTimestamp: tokenTimestamp,
        blockTimestamp: status.blockTimestamp
      }
    };
  }

  async #buildCreateTrade(
    intent: Extract<DomainIntent, { action: 'create_trade' }>
  ): Promise<BuiltPlan> {
    if (!intent.offerAsset || !intent.requestAsset) {
      return unsupported('The trade plan is missing required editable terms.');
    }
    const privateLiquidity = intent.amountVisibility === 'private';
    if (
      !privateLiquidity &&
      (!intent.offerAmount || !intent.requestAmount)
    ) {
      return unsupported('The visible trade plan is missing required amounts.');
    }
    const offerAmount = privateLiquidity
      ? 0n
      : asAtomic(intent.offerAmount!, intent.offerAsset);
    const requestAmount = privateLiquidity
      ? 0n
      : asAtomic(intent.requestAmount!, intent.requestAsset);

    if (intent.amountVisibility === 'private') {
      if (intent.offerAsset.kind !== 'private-erc20') {
        return unsupported(
          'Private liquidity requires a verified private ERC-20 on the offered side.'
        );
      }
      const contract = requireManifestContract(this.#manifest, 'privateEscrow');
      const selector = requireSelector(
        contract,
        'createPrivateOrderWithRecoveryNote'
      );
      const privateApproval = await this.#approvalSteps(
        intent.wallet!,
        intent.offerAsset,
        contract.address as Address,
        0n,
        'signer-elicitation',
        'hidden-offer-amount'
      );
      const unlisted = intent.access === 'unlisted';
      const recipient =
        intent.access === 'direct' ? intent.recipient : null;
      if (intent.access === 'direct' && !recipient) {
        return unsupported('Recipient-bound private liquidity needs a recipient.');
      }
      const values: PlanPrivateArtifactGroup['values'] = [
        artifactValue(
          'hidden-offer-amount',
          'uint256',
          'signer-elicitation',
          intent.offerAsset
        ),
        artifactValue(
          'hidden-request-amount',
          'uint256',
          'signer-elicitation',
          intent.requestAsset
        ),
        ...(unlisted
          ? []
          : [
              artifactValue(
                'public-offer-term',
                'uint256',
                'signer-elicitation',
                intent.offerAsset
              ),
              artifactValue(
                'public-request-term',
                'uint256',
                'signer-elicitation',
                intent.requestAsset
              )
            ]),
        ...(unlisted
          ? [artifactValue('order-access-secret', 'access-secret', 'generated-local')]
          : [])
      ];
      const outputs: PlanPrivateArtifactGroup['outputs'] = [
        {
          kind: 'itUint256',
          valueId: 'hidden-offer-amount',
          jsonPointer: '/arguments/7'
        },
        {
          kind: 'trade-recovery-v1',
          jsonPointer: '/arguments/10'
        },
        ...(!unlisted
          ? [
              {
                kind: 'uint256' as const,
                valueId: 'public-offer-term',
                jsonPointer: '/arguments/0/2'
              },
              {
                kind: 'uint256' as const,
                valueId: 'public-request-term',
                jsonPointer: '/arguments/1/2'
              }
            ]
          : []),
        ...(unlisted
          ? [
              {
                kind: 'keccak256' as const,
                valueId: 'order-access-secret',
                jsonPointer: '/arguments/5'
              },
              {
                kind: 'direct-terms-v1' as const,
                valueId: 'order-access-secret',
                jsonPointer: '/arguments/12'
              },
              {
                kind: 'terms-hash-v1' as const,
                jsonPointer: '/arguments/6'
              },
              {
                kind: 'itUint256' as const,
                valueId: 'hidden-offer-amount',
                jsonPointer: '/arguments/8'
              },
              {
                kind: 'itUint256' as const,
                valueId: 'hidden-request-amount',
                jsonPointer: '/arguments/9'
              },
              {
                kind: 'itUint256' as const,
                valueId: 'order-access-secret',
                jsonPointer: '/arguments/11'
              }
            ]
          : [])
      ];
      const protocolStep: PlanStep = {
        id: 'create-private-liquidity',
        kind: 'protocol',
        contract: contract.address as Address,
        description: `Create ${intent.access} private-liquidity ChainWhisper trade`,
        nativeValue: '0',
        gasCap: PRIVATE_WRITE_GAS_CAP.toString(),
        encoding: {
          selector,
          arguments: [
            assetTuple(intent.offerAsset, 0n),
            assetTuple(intent.requestAsset, 0n),
            recipient ?? ZERO_ADDRESS,
            isoToUnixSeconds(intent.expiresAt),
            intent.access === 'public',
            ZERO_BYTES32,
            ZERO_BYTES32,
            EMPTY_IT_UINT256,
            EMPTY_IT_UINT256,
            EMPTY_IT_UINT256,
            '0x',
            EMPTY_IT_UINT256,
            '0x'
          ]
        },
        privateArtifactGroups: [
          {
            id: 'private-liquidity-create-artifacts',
            recipe: 'private-liquidity-v1',
            values,
            outputs,
            context: {
              access: intent.access,
              maker: intent.wallet,
              recipient: recipient ?? null,
              expiresAt: intent.expiresAt
            }
          }
        ]
      };
      const steps = [...privateApproval, protocolStep];
      return {
        contract,
        steps,
        nativePrincipal: 0n,
        feeRequired: true,
        expectedResult: `A new ${intent.access} private-liquidity OTC order is opened.`
      };
    }

    if (intent.access !== 'public') {
      const contract = requireManifestContract(this.#manifest, 'directEscrow');
      const selector = requireSelector(contract, 'createDirectTrade');
      if (intent.access === 'direct' && !intent.recipient) {
        return unsupported('Recipient-bound Direct creation needs a recipient.');
      }
      const steps = await this.#approvalSteps(
        intent.wallet!,
        intent.offerAsset,
        contract.address as Address,
        offerAmount,
        'intent-sell-amount',
        'offer-amount'
      );
      const values: PlanPrivateArtifactGroup['values'] = [
        artifactValue('order-access-secret', 'access-secret', 'generated-local'),
        artifactValue(
          'offer-amount',
          'uint256',
          'intent-sell-amount',
          intent.offerAsset
        ),
        artifactValue(
          'request-amount',
          'uint256',
          'intent-buy-amount',
          intent.requestAsset
        )
      ];
      const outputs: PlanPrivateArtifactGroup['outputs'] = [
        {
          kind: 'keccak256',
          valueId: 'order-access-secret',
          jsonPointer: '/arguments/7'
        },
        {
          kind: 'direct-terms-v1',
          valueId: 'order-access-secret',
          jsonPointer: '/arguments/10'
        },
        {
          kind: 'terms-hash-v1',
          jsonPointer: '/arguments/8'
        },
        {
          kind: 'itUint256',
          valueId: 'order-access-secret',
          jsonPointer: '/arguments/9'
        },
        ...(intent.offerAsset.kind === 'private-erc20'
          ? [
              {
                kind: 'itUint256' as const,
                valueId: 'offer-amount',
                jsonPointer: '/arguments/3'
              }
            ]
          : []),
        ...(intent.requestAsset.kind === 'private-erc20'
          ? [
              {
                kind: 'itUint256' as const,
                valueId: 'request-amount',
                jsonPointer: '/arguments/4'
              }
            ]
          : [])
      ];
      steps.push({
        id: 'create-direct-trade',
        kind: 'protocol',
        contract: contract.address as Address,
        description: `Create ${intent.access} ChainWhisper trade`,
        nativeValue:
          intent.offerAsset.kind === 'native' ? offerAmount.toString() : '0',
        gasCap: PRIVATE_WRITE_GAS_CAP.toString(),
        encoding: {
          selector,
          arguments: [
            recurringAssetTuple(intent.offerAsset),
            recurringAssetTuple(intent.requestAsset),
            [
              intent.offerAsset.kind === 'private-erc20'
                ? '0'
                : offerAmount.toString(),
              intent.requestAsset.kind === 'private-erc20'
                ? '0'
                : requestAmount.toString()
            ],
            EMPTY_IT_UINT256,
            EMPTY_IT_UINT256,
            intent.access === 'direct'
              ? intent.recipient ?? ZERO_ADDRESS
              : ZERO_ADDRESS,
            isoToUnixSeconds(intent.expiresAt),
            ZERO_BYTES32,
            ZERO_BYTES32,
            EMPTY_IT_UINT256,
            '0x'
          ]
        },
        privateArtifactGroups: [
          {
            id: 'direct-create-artifacts',
            recipe: 'direct-order-v1',
            values,
            outputs,
            context: {
              access: intent.access,
              maker: intent.wallet,
              recipient:
                intent.access === 'direct' ? intent.recipient ?? null : null,
              expiresAt: intent.expiresAt
            }
          }
        ]
      });
      return {
        contract,
        steps,
        nativePrincipal:
          intent.offerAsset.kind === 'native' ? offerAmount : 0n,
        feeRequired: true,
        expectedResult: `A new ${intent.access} one-off OTC order is opened.`
      };
    }

    const contract = requireManifestContract(this.#manifest, 'standardEscrow');
    const selector = requireSelector(contract, 'createTradeWithPolicy');
    assertUint128(offerAmount, 'Offer amount');
    assertUint128(requestAmount, 'Request amount');
    const steps = await this.#approvalSteps(
      intent.wallet!,
      intent.offerAsset,
      contract.address as Address,
      offerAmount,
      'intent-sell-amount'
    );
    steps.push({
      id: 'create-trade',
      kind: 'protocol',
      contract: contract.address as Address,
      description: 'Create public ChainWhisper trade',
      nativeValue:
        intent.offerAsset.kind === 'native' ? offerAmount.toString() : '0',
      encoding: {
        selector,
        arguments: [
          assetTuple(intent.offerAsset, offerAmount),
          assetTuple(intent.requestAsset, requestAmount),
          ZERO_ADDRESS,
          isoToUnixSeconds(intent.expiresAt),
          true,
          ZERO_BYTES32,
          '0',
          [
            intent.fillPolicy.partialFillsAllowed,
            intent.fillPolicy.minPartialFillBps,
            asOptionalAtomic(
              intent.fillPolicy.minRequestAmount,
              intent.requestAsset
            ).toString(),
            asOptionalAtomic(
              intent.fillPolicy.maxRequestAmountPerWallet,
              intent.requestAsset
            ).toString(),
            intent.fillPolicy.oneFillPerWallet
          ]
        ]
      }
    });
    return {
      contract,
      steps,
      nativePrincipal:
        intent.offerAsset.kind === 'native' ? offerAmount : 0n,
      feeRequired: true,
      expectedResult: 'A new public one-off OTC order is opened.'
    };
  }

  async #buildCreateRecurring(
    intent: Extract<DomainIntent, { action: 'create_recurring' }>
  ): Promise<BuiltPlan> {
    if (
      !intent.baseAsset ||
      !intent.quoteAsset ||
      !intent.buyPrice ||
      !intent.sellPrice
    ) {
      return unsupported('The recurring plan is missing required editable terms.');
    }
    if (intent.access === 'unlisted') {
      return unsupported(
        'Recurring orders support only public or fixed-recipient access.'
      );
    }
    if (intent.access === 'direct' && !intent.recipient) {
      return unsupported('A direct recurring order requires its fixed recipient.');
    }
    const contract = requireManifestContract(this.#manifest, 'recurringEscrow');
    const baseUnit = 10n ** BigInt(intent.baseAsset.decimals);
    const buyQuote = asAtomic(intent.buyPrice, intent.quoteAsset);
    const sellQuote = asAtomic(intent.sellPrice, intent.quoteAsset);
    const baseLiquidity = asOptionalAtomic(
      intent.sellBaseLiquidity,
      intent.baseAsset
    );
    const quoteLiquidity = asOptionalAtomic(
      intent.buyQuoteLiquidity,
      intent.quoteAsset
    );
    const privateInventory = intent.amountVisibility === 'private';
    if (
      !privateInventory &&
      baseLiquidity <= 0n &&
      quoteLiquidity <= 0n
    ) {
      return unsupported('Fund at least one recurring liquidity side.');
    }
    if (
      privateInventory &&
      intent.baseAsset.kind !== 'private-erc20' &&
      intent.quoteAsset.kind !== 'private-erc20'
    ) {
      return unsupported(
        'Private recurring inventory requires at least one private ERC-20 side.'
      );
    }
    const baseValueId = 'recurring-base-inventory';
    const quoteValueId = 'recurring-quote-inventory';
    const baseSource: PlanPrivateArtifactValueSource =
      intent.baseAsset.kind === 'private-erc20' && privateInventory
        ? 'signer-elicitation'
        : intent.sellBaseLiquidity
          ? 'recurring-sell-base-liquidity'
          : 'constant-zero';
    const quoteSource: PlanPrivateArtifactValueSource =
      intent.quoteAsset.kind === 'private-erc20' && privateInventory
        ? 'signer-elicitation'
        : intent.buyQuoteLiquidity
          ? 'recurring-buy-quote-liquidity'
          : 'constant-zero';
    const steps = [
      ...(await this.#approvalSteps(
        intent.wallet!,
        intent.baseAsset,
        contract.address as Address,
        baseLiquidity,
        baseSource,
        baseValueId,
        privateInventory && intent.baseAsset.kind === 'private-erc20'
      )),
      ...(await this.#approvalSteps(
        intent.wallet!,
        intent.quoteAsset,
        contract.address as Address,
        quoteLiquidity,
        quoteSource,
        quoteValueId,
        privateInventory && intent.quoteAsset.kind === 'private-erc20'
      ))
    ];
    const selectorName = privateInventory
      ? 'createPrivateRecurringOrderWithRecoveryNote'
      : 'createRecurringOrder';
    const selector = requireSelector(contract, selectorName);
    const basePublicInventory =
      privateInventory && intent.baseAsset.kind === 'private-erc20'
        ? 0n
        : baseLiquidity;
    const quotePublicInventory =
      privateInventory && intent.quoteAsset.kind === 'private-erc20'
        ? 0n
        : quoteLiquidity;
    const protocolArguments: unknown[] = [
      recurringAssetTuple(intent.baseAsset),
      recurringAssetTuple(intent.quoteAsset),
      [baseUnit.toString(), buyQuote.toString()],
      [baseUnit.toString(), sellQuote.toString()],
      intent.access === 'direct'
        ? intent.recipient ?? ZERO_ADDRESS
        : ZERO_ADDRESS,
      intent.access === 'public',
      ZERO_BYTES32,
      basePublicInventory.toString(),
      quotePublicInventory.toString()
    ];
    let privateArtifactGroups: PlanPrivateArtifactGroup[] | undefined;
    if (privateInventory) {
      protocolArguments.push(
        EMPTY_IT_UINT256,
        EMPTY_IT_UINT256,
        '0x'
      );
      const basePrivateInputId =
        intent.baseAsset.kind === 'private-erc20'
          ? baseValueId
          : 'recurring-base-private-zero';
      const quotePrivateInputId =
        intent.quoteAsset.kind === 'private-erc20'
          ? quoteValueId
          : 'recurring-quote-private-zero';
      const values: PlanPrivateArtifactGroup['values'] = [
        artifactValue(
          baseValueId,
          'uint256',
          baseSource,
          intent.baseAsset,
          true
        ),
        artifactValue(
          quoteValueId,
          'uint256',
          quoteSource,
          intent.quoteAsset,
          true
        ),
        ...(basePrivateInputId === baseValueId
          ? []
          : [
              artifactValue(
                basePrivateInputId,
                'uint256',
                'constant-zero',
                intent.baseAsset,
                true
              )
            ]),
        ...(quotePrivateInputId === quoteValueId
          ? []
          : [
              artifactValue(
                quotePrivateInputId,
                'uint256',
                'constant-zero',
                intent.quoteAsset,
                true
              )
            ])
      ];
      privateArtifactGroups = [
        {
          id: 'private-recurring-create-artifacts',
          recipe: 'private-recurring-v1',
          values,
          outputs: [
            {
              kind: 'itUint256',
              valueId: basePrivateInputId,
              jsonPointer: '/arguments/9'
            },
            {
              kind: 'itUint256',
              valueId: quotePrivateInputId,
              jsonPointer: '/arguments/10'
            },
            {
              kind: 'recurring-recovery-v1',
              jsonPointer: '/arguments/11'
            }
          ],
          context: {
            access: intent.access,
            maker: intent.wallet,
            recipient:
              intent.access === 'direct'
                ? intent.recipient ?? null
                : null,
            requirePositiveValueIds: `${baseValueId},${quoteValueId}`
          }
        }
      ];
    }
    steps.push({
      id: privateInventory
        ? 'create-private-recurring'
        : 'create-recurring',
      kind: 'protocol',
      contract: contract.address as Address,
      description: `Create ${intent.access} ${privateInventory ? 'private-inventory ' : ''}recurring ChainWhisper order`,
      nativeValue: (
        (intent.baseAsset.kind === 'native' ? basePublicInventory : 0n) +
        (intent.quoteAsset.kind === 'native' ? quotePublicInventory : 0n)
      ).toString(),
      gasCap: privateInventory
        ? PRIVATE_WRITE_GAS_CAP.toString()
        : RECURRING_GAS_CAP.toString(),
      encoding: {
        selector,
        arguments: protocolArguments
      },
      ...(privateArtifactGroups ? { privateArtifactGroups } : {})
    });
    return {
      contract,
      steps,
      nativePrincipal:
        (intent.baseAsset.kind === 'native' ? basePublicInventory : 0n) +
        (intent.quoteAsset.kind === 'native' ? quotePublicInventory : 0n),
      feeRequired: true,
      expectedResult: `A ${intent.access} ${privateInventory ? 'private-inventory ' : ''}recurring OTC order is opened.`
    };
  }

  async #buildFill(
    intent: Extract<DomainIntent, { action: 'fill' }>
  ): Promise<BuiltPlan> {
    if (intent.order.kind === 'recurring') {
      if (
        !intent.order.recurring ||
        intent.order.access === 'unlisted'
      ) {
        return unsupported(
          'Unlisted recurring fills are disabled because the deployed reusable access secret would be public calldata.'
        );
      }
      if (!intent.recurringSide) {
        return unsupported('Choose the recurring side.');
      }
      const contract = requireManifestContract(
        this.#manifest,
        'recurringEscrow'
      );
      if (
        intent.order.identity.escrowContract.toLowerCase() !==
        contract.address.toLowerCase()
      ) {
        return unsupported(
          'The recurring order is not handled by the audited recurring escrow.'
        );
      }
      // recurringSide is the user's side. Buying base pays quote into the
      // maker's sell side; selling base pays base into the maker's buy side.
      const userBuysBase = intent.recurringSide === 'buy';
      const inputAsset = userBuysBase
        ? intent.order.recurring.quoteAsset
        : intent.order.recurring.baseAsset;
      const outputAsset = userBuysBase
        ? intent.order.recurring.baseAsset
        : intent.order.recurring.quoteAsset;
      const privateInventory =
        intent.order.amountVisibility === 'private';
      const signerLocalInput =
        privateInventory && inputAsset.kind === 'private-erc20';
      if (!signerLocalInput && !intent.inputAmount) {
        return unsupported('Enter the recurring fill input amount.');
      }
      const inputAmount = signerLocalInput
        ? 0n
        : asAtomic(intent.inputAmount!, inputAsset);
      const minOutput = intent.minOutputAmount
        ? asAtomic(intent.minOutputAmount, outputAsset)
        : 0n;
      const selectorName = privateInventory
        ? userBuysBase
          ? 'fillPrivateSellSideWithSecret'
          : 'fillPrivateBuySideWithSecret'
        : userBuysBase
          ? 'fillSellSideWithSecret'
          : 'fillBuySideWithSecret';
      const selector = requireSelector(contract, selectorName);
      const steps = await this.#approvalSteps(
        intent.wallet!,
        inputAsset,
        contract.address as Address,
        inputAmount,
        signerLocalInput ? 'signer-elicitation' : 'intent-sell-amount',
        'recurring-fill-input'
      );
      const protocolArguments: unknown[] = privateInventory
        ? [
            intent.order.identity.localId,
            signerLocalInput ? '0' : inputAmount.toString(),
            EMPTY_IT_UINT256,
            minOutput.toString(),
            ZERO_BYTES32
          ]
        : [
            intent.order.identity.localId,
            inputAmount.toString(),
            minOutput.toString(),
            ZERO_BYTES32
          ];
      const privateArtifactGroups: PlanPrivateArtifactGroup[] | undefined =
        privateInventory
          ? [
              {
                id: 'private-recurring-fill-artifacts',
                recipe: 'private-recurring-fill-v1',
                values: [
                  artifactValue(
                    signerLocalInput
                      ? 'recurring-fill-input'
                      : 'recurring-fill-private-zero',
                    'uint256',
                    signerLocalInput
                      ? 'signer-elicitation'
                      : 'constant-zero',
                    inputAsset,
                    !signerLocalInput
                  )
                ],
                outputs: [
                  {
                    kind: 'itUint256',
                    valueId: signerLocalInput
                      ? 'recurring-fill-input'
                      : 'recurring-fill-private-zero',
                    jsonPointer: '/arguments/2'
                  }
                ],
                context: {
                  side: intent.recurringSide,
                  inputPrivate: signerLocalInput
                }
              }
            ]
          : undefined;
      steps.push({
        id: 'fill-recurring',
        kind: 'protocol',
        contract: contract.address as Address,
        description: `${userBuysBase ? 'Buy' : 'Sell'} base through recurring ChainWhisper order ${intent.order.identity.localId}`,
        nativeValue:
          inputAsset.kind === 'native' ? inputAmount.toString() : '0',
        gasCap: privateInventory
          ? PRIVATE_WRITE_GAS_CAP.toString()
          : RECURRING_GAS_CAP.toString(),
        encoding: {
          selector,
          arguments: protocolArguments
        },
        ...(privateArtifactGroups ? { privateArtifactGroups } : {})
      });
      return {
        contract,
        steps,
        nativePrincipal:
          inputAsset.kind === 'native' ? inputAmount : 0n,
        feeRequired: false,
        expectedResult: `The ${privateInventory ? 'private-inventory ' : ''}recurring order ${userBuysBase ? 'sells base to' : 'buys base from'} the user within the signed minimum output.`
      };
    }
    const directContract = requireManifestContract(
      this.#manifest,
      'directEscrow'
    );
    if (
      intent.order.identity.escrowContract.toLowerCase() ===
      directContract.address.toLowerCase()
    ) {
      if (
        intent.order.access !== 'direct' &&
        intent.order.access !== 'unlisted'
      ) {
        return unsupported(
          'The audited Direct escrow order has an invalid access classification.'
        );
      }
      if (
        intent.order.access === 'direct' &&
        intent.order.recipient?.toLowerCase() !== intent.wallet!.toLowerCase()
      ) {
        return unsupported(
          'Only the trusted recipient can fill this Direct order.'
        );
      }
      if (intent.minOutputAmount) {
        return unsupported(
          'Direct orders settle their exact signed terms and do not accept a separate minimum output.'
        );
      }
      const requestIsPrivate =
        intent.order.requestAsset.kind === 'private-erc20';
      if (!requestIsPrivate && !intent.inputAmount) {
        return unsupported(
          'Enter the exact Direct order payment amount.'
        );
      }
      const inputAmount = requestIsPrivate
        ? 0n
        : asAtomic(intent.inputAmount!, intent.order.requestAsset);
      const steps = await this.#approvalSteps(
        intent.wallet!,
        intent.order.requestAsset,
        directContract.address as Address,
        inputAmount,
        requestIsPrivate ? 'signer-elicitation' : 'intent-sell-amount',
        requestIsPrivate ? 'request-amount' : undefined
      );
      const needsAccessSecret = intent.order.access === 'unlisted';
      const isCounter = intent.order.relation?.kind === 'counter';
      if (isCounter && needsAccessSecret) {
        return unsupported(
          'A Direct counterorder must be fixed-recipient, not unlisted.'
        );
      }
      const selectorName = isCounter
        ? 'acceptCounterTradeAndCloseParent'
        : needsAccessSecret
          ? 'acceptDirectTradeWithEncryptedAccess'
          : 'acceptDirectTrade';
      const values: PlanPrivateArtifactGroup['values'] = [
        ...(requestIsPrivate
          ? [
              artifactValue(
                'request-amount',
                'uint256',
                'signer-elicitation',
                intent.order.requestAsset
              )
            ]
          : []),
        ...(needsAccessSecret
          ? [
              artifactValue(
                'order-access-secret',
                'access-secret',
                'local-order-vault'
              )
            ]
          : [])
      ];
      const outputs: PlanPrivateArtifactGroup['outputs'] = [
        ...(requestIsPrivate
          ? [
              {
                kind: 'itUint256' as const,
                valueId: 'request-amount',
                jsonPointer: '/arguments/1'
              }
            ]
          : []),
        ...(needsAccessSecret
          ? [
              {
                kind: 'itUint256' as const,
                valueId: 'order-access-secret',
                jsonPointer: '/arguments/2'
              }
            ]
          : [])
      ];
      steps.push({
        id: 'fill-direct-trade',
        kind: 'protocol',
        contract: directContract.address as Address,
        description: `Fill ${intent.order.access} ChainWhisper order ${intent.order.identity.localId}`,
        nativeValue:
          intent.order.requestAsset.kind === 'native'
            ? inputAmount.toString()
            : '0',
        gasCap: PRIVATE_WRITE_GAS_CAP.toString(),
        encoding: {
          selector: requireSelector(directContract, selectorName),
          arguments: [
            intent.order.identity.localId,
            EMPTY_IT_UINT256,
            ...(!isCounter && needsAccessSecret
              ? [EMPTY_IT_UINT256]
              : [])
          ]
        },
        ...(values.length
          ? {
              privateArtifactGroups: [
                {
                  id: 'direct-fill-artifacts',
                  recipe: 'private-fill-v1' as const,
                  values,
                  outputs,
                  context: {
                    orderHandle: intent.order.identity.handle,
                    access: intent.order.access,
                    recipient: intent.order.recipient,
                    relation: isCounter ? 'counter' : 'primary'
                  }
                }
              ]
            }
          : {})
      });
      return {
        contract: directContract,
        steps,
        nativePrincipal:
          intent.order.requestAsset.kind === 'native' ? inputAmount : 0n,
        feeRequired: false,
        expectedResult: isCounter
          ? 'The selected Direct counterorder is filled and its parent order is closed atomically.'
          : `The selected ${intent.order.access} Direct order is filled.`
      };
    }

    const privateContract = requireManifestContract(
      this.#manifest,
      'privateEscrow'
    );
    if (
      intent.order.identity.escrowContract.toLowerCase() ===
      privateContract.address.toLowerCase()
    ) {
      if (intent.order.amountVisibility !== 'private') {
        return unsupported(
          'The audited private escrow order is missing its private-liquidity classification.'
        );
      }
      if (
        intent.order.access === 'direct' &&
        intent.order.recipient?.toLowerCase() !== intent.wallet!.toLowerCase()
      ) {
        return unsupported(
          'Only the trusted recipient can fill this private-liquidity order.'
        );
      }
      if (intent.minOutputAmount) {
        return unsupported(
          'Private-liquidity output limits are confidential signer inputs, not public planner fields.'
        );
      }
      const requestIsPrivate =
        intent.order.requestAsset.kind === 'private-erc20';
      const inputAmount = requestIsPrivate
        ? 0n
        : intent.inputAmount
          ? asAtomic(intent.inputAmount, intent.order.requestAsset)
          : unsupported('Enter the public or native payment amount.');
      const steps = await this.#approvalSteps(
        intent.wallet!,
        intent.order.requestAsset,
        privateContract.address as Address,
        inputAmount,
        requestIsPrivate ? 'signer-elicitation' : 'intent-sell-amount',
        requestIsPrivate ? 'request-amount' : undefined
      );
      const needsAccessSecret = intent.order.access === 'unlisted';
      const selectorName = requestIsPrivate
        ? needsAccessSecret
          ? 'fillPrivateOrderWithEncryptedAccess'
          : 'fillPrivateOrder'
        : needsAccessSecret
          ? 'fillHybridPrivateOrderWithEncryptedAccess'
          : 'fillHybridPrivateOrder';
      const values: PlanPrivateArtifactGroup['values'] = [
        ...(requestIsPrivate
          ? [
              artifactValue(
                'request-amount',
                'uint256',
                'signer-elicitation',
                intent.order.requestAsset
              )
            ]
          : []),
        ...(needsAccessSecret
          ? [
              artifactValue(
                'order-access-secret',
                'access-secret',
                'local-order-vault'
              )
            ]
          : [])
      ];
      const outputs: PlanPrivateArtifactGroup['outputs'] = [
        ...(requestIsPrivate
          ? [
              {
                kind: 'itUint256' as const,
                valueId: 'request-amount',
                jsonPointer: '/arguments/1'
              }
            ]
          : []),
        ...(needsAccessSecret
          ? [
              {
                kind: 'itUint256' as const,
                valueId: 'order-access-secret',
                jsonPointer: '/arguments/2'
              }
            ]
          : [])
      ];
      steps.push({
        id: 'fill-private-liquidity',
        kind: 'protocol',
        contract: privateContract.address as Address,
        description: `Fill ${intent.order.access} private-liquidity order ${intent.order.identity.localId}`,
        nativeValue:
          intent.order.requestAsset.kind === 'native'
            ? inputAmount.toString()
            : '0',
        gasCap: PRIVATE_WRITE_GAS_CAP.toString(),
        encoding: {
          selector: requireSelector(privateContract, selectorName),
          arguments: [
            intent.order.identity.localId,
            requestIsPrivate
              ? EMPTY_IT_UINT256
              : inputAmount.toString(),
            ...(needsAccessSecret ? [EMPTY_IT_UINT256] : [])
          ]
        },
        ...(values.length
          ? {
              privateArtifactGroups: [
                {
                  id: 'private-fill-artifacts',
                  recipe: 'private-fill-v1' as const,
                  values,
                  outputs,
                  context: {
                    orderHandle: intent.order.identity.handle,
                    access: intent.order.access,
                    recipient: intent.order.recipient
                  }
                }
              ]
            }
          : {})
      });
      return {
        contract: privateContract,
        steps,
        nativePrincipal:
          intent.order.requestAsset.kind === 'native' ? inputAmount : 0n,
        feeRequired: false,
        expectedResult:
          'The selected private-liquidity order is filled using signer-local confidential inputs.'
      };
    }

    const contract = requireManifestContract(this.#manifest, 'standardEscrow');
    if (
      intent.order.identity.escrowContract.toLowerCase() !==
      contract.address.toLowerCase()
    ) {
      return unsupported('The order is not handled by the audited standard escrow.');
    }
    const legacyStandardRecipientBound =
      intent.order.legacyCompatibility?.kind ===
      'standard-recipient-bound';
    if (
      intent.order.amountVisibility !== 'visible' ||
      (
        intent.order.access !== 'public' &&
        !legacyStandardRecipientBound
      )
    ) {
      return unsupported(
        'The order access route does not match an audited ChainWhisper escrow.'
      );
    }
    if (
      legacyStandardRecipientBound &&
      (
        intent.order.access !== 'direct' ||
        !intent.order.recipient ||
        intent.order.recipient.toLowerCase() !==
          intent.wallet!.toLowerCase()
      )
    ) {
      return unsupported(
        'Only the fixed recipient can fill this legacy Standard order.'
      );
    }
    if (!intent.inputAmount) {
      return unsupported('The fill amount is missing.');
    }
    const inputAmount = asAtomic(
      intent.inputAmount,
      intent.order.requestAsset
    );
    const legacyCounterAcceptance =
      legacyStandardRecipientBound &&
      intent.order.relation?.kind === 'counter';
    if (legacyCounterAcceptance) {
      if (intent.minOutputAmount) {
        return unsupported(
          'Legacy Standard counter acceptance does not accept a separate output limit.'
        );
      }
      const trustedRemaining = intent.order.remainingRequestAmount ??
        intent.order.requestAmount;
      if (
        !trustedRemaining ||
        inputAmount !==
          asAtomic(trustedRemaining, intent.order.requestAsset)
      ) {
        return unsupported(
          'Legacy Standard counter acceptance requires the exact trusted remaining payment.'
        );
      }
      const steps = await this.#approvalSteps(
        intent.wallet!,
        intent.order.requestAsset,
        contract.address as Address,
        inputAmount,
        'trusted-order-visible-amount'
      );
      steps.push({
        id: 'accept-legacy-standard-counter',
        kind: 'protocol',
        contract: contract.address as Address,
        description: `Accept legacy Standard recipient-bound counterorder ${intent.order.identity.localId}`,
        nativeValue:
          intent.order.requestAsset.kind === 'native'
            ? inputAmount.toString()
            : '0',
        encoding: {
          selector: requireSelector(
            contract,
            'acceptCounterTradeAndCloseParent'
          ),
          arguments: [intent.order.identity.localId]
        }
      });
      return {
        contract,
        steps,
        nativePrincipal:
          intent.order.requestAsset.kind === 'native'
            ? inputAmount
            : 0n,
        feeRequired: false,
        expectedResult:
          'The legacy Standard recipient-bound counterorder is accepted for its exact remaining terms and its parent is closed atomically.'
      };
    }
    const selector = requireSelector(contract, 'fillTrade');
    const minOutput = intent.minOutputAmount
      ? asAtomic(intent.minOutputAmount, intent.order.offerAsset)
      : 0n;
    const steps = await this.#approvalSteps(
      intent.wallet!,
      intent.order.requestAsset,
      contract.address as Address,
      inputAmount,
      'intent-sell-amount'
    );
    steps.push({
      id: 'fill-trade',
      kind: 'protocol',
      contract: contract.address as Address,
      description: `Fill ChainWhisper order ${intent.order.identity.localId}`,
      nativeValue:
        intent.order.requestAsset.kind === 'native'
          ? inputAmount.toString()
          : '0',
      encoding: {
        selector,
        arguments: [
          intent.order.identity.localId,
          inputAmount.toString(),
          minOutput.toString()
        ]
      }
    });
    return {
      contract,
      steps,
      nativePrincipal:
        intent.order.requestAsset.kind === 'native' ? inputAmount : 0n,
      feeRequired: false,
      expectedResult: legacyStandardRecipientBound
        ? 'The legacy Standard recipient-bound order is filled by its fixed recipient within the signed limits.'
        : 'The selected public order is filled within the signed limits.'
    };
  }

  async #buildCounter(
    intent: Extract<DomainIntent, { action: 'counter' }>
  ): Promise<BuiltPlan> {
    if (intent.order.kind !== 'trade') {
      return unsupported('Recurring orders do not support counterorders.');
    }
    if (intent.order.status !== 'open') {
      return unsupported('Only an open one-off order can be countered.');
    }
    if (
      intent.recipient.toLowerCase() !== intent.order.maker.toLowerCase() ||
      intent.access !== 'direct'
    ) {
      return unsupported(
        'A counterorder must be Direct and fixed to the original maker.'
      );
    }
    if (
      intent.wallet!.toLowerCase() ===
      intent.order.maker.toLowerCase()
    ) {
      return unsupported(
        'The maker cannot create a counter addressed back to the same maker.'
      );
    }
    const contract = requireManifestContract(this.#manifest, 'directEscrow');
    const sourceAddress =
      intent.order.identity.escrowContract.toLowerCase();
    const directSource =
      sourceAddress === contract.address.toLowerCase();
    const standardContract = requireManifestContract(
      this.#manifest,
      'standardEscrow'
    );
    const privateContract = requireManifestContract(
      this.#manifest,
      'privateEscrow'
    );
    if (
      !directSource &&
      sourceAddress !== standardContract.address.toLowerCase() &&
      sourceAddress !== privateContract.address.toLowerCase()
    ) {
      return unsupported(
        'The countered order is not handled by an audited one-off escrow.'
      );
    }

    const sourceRelation = intent.order.relation?.kind ?? 'primary';
    const legacyStandardCounterReplacement =
      sourceAddress === standardContract.address.toLowerCase() &&
      sourceRelation === 'counter' &&
      intent.order.legacyCompatibility?.kind ===
        'standard-recipient-bound';
    if (legacyStandardCounterReplacement) {
      return this.#buildLegacyStandardCounterReplacement(
        intent,
        standardContract
      );
    }
    const directCounterOfCounter =
      directSource && sourceRelation === 'counter';
    if (
      intent.order.access === 'direct' &&
      intent.order.recipient &&
      intent.wallet!.toLowerCase() !==
        intent.order.recipient.toLowerCase()
    ) {
      return unsupported(
        directCounterOfCounter
          ? 'Only the recipient of a Direct counter can supersede it.'
          : 'Only the fixed recipient can counter this Direct order.'
      );
    }
    if (
      directCounterOfCounter &&
      !intent.order.relation?.parentOrder
    ) {
      return unsupported(
        'The Direct counter is missing its trusted parent order.'
      );
    }
    const parent =
      intent.order.relation?.parentOrder ?? intent.order.identity;
    if (!directSource) {
      const parentAddress = parent.escrowContract.toLowerCase();
      if (
        parentAddress !== standardContract.address.toLowerCase() &&
        parentAddress !== privateContract.address.toLowerCase()
      ) {
        return unsupported(
          'The cross-escrow counter is missing its trusted Standard or Private parent.'
        );
      }
      if (
        !(await this.#readDirectCounterTrust(
          parent.escrowContract,
          contract.address as Address
        ))
      ) {
        return unsupported(
          'The parent escrow does not currently trust the deployed Direct counter escrow.'
        );
      }
    }

    const offerPrivate = intent.offerAsset.kind === 'private-erc20';
    const requestPrivate = intent.requestAsset.kind === 'private-erc20';
    if (!offerPrivate && !intent.offerAmount) {
      return unsupported('Enter the public or native counter offer amount.');
    }
    if (!requestPrivate && !intent.requestAmount) {
      return unsupported('Enter the public or native counter request amount.');
    }
    const offerAmount = offerPrivate
      ? 0n
      : asAtomic(intent.offerAmount!, intent.offerAsset);
    const requestAmount = requestPrivate
      ? 0n
      : asAtomic(intent.requestAmount!, intent.requestAsset);
    const offerSource: PlanPrivateArtifactValueSource = offerPrivate
      ? 'signer-elicitation'
      : 'intent-sell-amount';
    const requestSource: PlanPrivateArtifactValueSource = requestPrivate
      ? 'signer-elicitation'
      : 'intent-buy-amount';
    const steps = await this.#approvalSteps(
      intent.wallet!,
      intent.offerAsset,
      contract.address as Address,
      offerAmount,
      offerSource,
      'offer-amount'
    );

    const counterRoute = !directSource
      ? 'cross-escrow'
      : directCounterOfCounter
        ? 'direct-counter'
        : 'direct-primary';
    const selectorName = !directSource
      ? 'createDirectCounterTradeForParent'
      : directCounterOfCounter
        ? 'counterTradeAndCloseCounteredTrade'
        : 'createDirectCounterTrade';
    const selector = requireSelector(contract, selectorName);
    const publicAmounts = [
      offerPrivate ? '0' : offerAmount.toString(),
      requestPrivate ? '0' : requestAmount.toString()
    ];
    const encryptedOfferIndex = directSource ? 4 : 6;
    const encryptedRequestIndex = directSource ? 5 : 7;
    const accessHashIndex = directSource ? 7 : 9;
    const termsHashIndex = directSource ? 8 : 10;
    const encryptedAccessIndex = directSource ? 9 : 11;
    const termsPayloadIndex = directSource ? 10 : 12;
    const protocolArguments: unknown[] = directSource
      ? [
          intent.order.identity.localId,
          recurringAssetTuple(intent.offerAsset),
          recurringAssetTuple(intent.requestAsset),
          publicAmounts,
          EMPTY_IT_UINT256,
          EMPTY_IT_UINT256,
          isoToUnixSeconds(intent.expiresAt),
          ZERO_BYTES32,
          ZERO_BYTES32,
          EMPTY_IT_UINT256,
          '0x'
        ]
      : [
          parent.escrowContract,
          parent.localId,
          intent.recipient,
          recurringAssetTuple(intent.offerAsset),
          recurringAssetTuple(intent.requestAsset),
          publicAmounts,
          EMPTY_IT_UINT256,
          EMPTY_IT_UINT256,
          isoToUnixSeconds(intent.expiresAt),
          ZERO_BYTES32,
          ZERO_BYTES32,
          EMPTY_IT_UINT256,
          '0x'
        ];
    const values: PlanPrivateArtifactGroup['values'] = [
      artifactValue(
        'order-access-secret',
        'access-secret',
        'generated-local'
      ),
      artifactValue(
        'offer-amount',
        'uint256',
        offerSource,
        intent.offerAsset
      ),
      artifactValue(
        'request-amount',
        'uint256',
        requestSource,
        intent.requestAsset
      )
    ];
    const outputs: PlanPrivateArtifactGroup['outputs'] = [
      {
        kind: 'keccak256',
        valueId: 'order-access-secret',
        jsonPointer: `/arguments/${accessHashIndex}`
      },
      {
        kind: 'terms-hash-v1',
        jsonPointer: `/arguments/${termsHashIndex}`
      },
      {
        kind: 'itUint256',
        valueId: 'order-access-secret',
        jsonPointer: `/arguments/${encryptedAccessIndex}`
      },
      {
        kind: 'direct-terms-v1',
        valueId: 'order-access-secret',
        jsonPointer: `/arguments/${termsPayloadIndex}`
      },
      ...(offerPrivate
        ? [
            {
              kind: 'itUint256' as const,
              valueId: 'offer-amount',
              jsonPointer: `/arguments/${encryptedOfferIndex}`
            }
          ]
        : []),
      ...(requestPrivate
        ? [
            {
              kind: 'itUint256' as const,
              valueId: 'request-amount',
              jsonPointer: `/arguments/${encryptedRequestIndex}`
            }
          ]
        : [])
    ];
    steps.push({
      id: 'create-direct-counter',
      kind: 'protocol',
      contract: contract.address as Address,
      description: `Create a Direct counterorder for ${parent.escrowContract}:${parent.localId}`,
      nativeValue:
        intent.offerAsset.kind === 'native'
          ? offerAmount.toString()
          : '0',
      gasCap: PRIVATE_WRITE_GAS_CAP.toString(),
      encoding: {
        selector,
        arguments: protocolArguments
      },
      privateArtifactGroups: [
        {
          id: 'direct-counter-artifacts',
          recipe: 'direct-counter-v1',
          values,
          outputs,
          context: {
            access: 'direct',
            maker: intent.wallet,
            recipient: intent.recipient,
            counterRoute,
            sourceOrderRelation: sourceRelation,
            sourceMaker: intent.order.maker,
            sourceRecipient: intent.order.recipient,
            parentEscrowContract: parent.escrowContract,
            parentTradeId: parent.localId,
            counteredEscrowContract:
              intent.order.identity.escrowContract,
            counteredTradeId: intent.order.identity.localId
          }
        }
      ]
    });
    return {
      contract,
      steps,
      nativePrincipal:
        intent.offerAsset.kind === 'native' ? offerAmount : 0n,
      feeRequired: true,
      expectedResult:
        'A recipient-bound Direct counterorder is created and linked to the verified parent order.'
    };
  }

  async #buildLegacyStandardCounterReplacement(
    intent: Extract<DomainIntent, { action: 'counter' }>,
    contract: RuntimeContractManifestEntry
  ): Promise<BuiltPlan> {
    if (
      intent.order.orderType ||
      intent.order.amountVisibility !== 'visible' ||
      intent.order.access !== 'direct' ||
      intent.order.relation?.kind !== 'counter' ||
      !intent.order.relation.parentOrder ||
      intent.order.relation.parentOrder.escrowContract.toLowerCase() !==
        contract.address.toLowerCase()
    ) {
      return unsupported(
        'Legacy Standard counter replacement requires a trusted recipient-bound Standard counter and its Standard parent.'
      );
    }
    if (
      !intent.order.recipient ||
      intent.order.recipient.toLowerCase() !==
        intent.wallet!.toLowerCase()
    ) {
      return unsupported(
        'Only the fixed recipient can supersede this legacy Standard counter.'
      );
    }
    if (!intent.offerAmount || !intent.requestAmount) {
      return unsupported(
        'Legacy Standard counter replacement requires both visible counter amounts.'
      );
    }
    const offerAmount = asAtomic(
      intent.offerAmount,
      intent.offerAsset
    );
    const requestAmount = asAtomic(
      intent.requestAmount,
      intent.requestAsset
    );
    assertUint128(offerAmount, 'Legacy counter offer amount');
    assertUint128(requestAmount, 'Legacy counter request amount');
    const steps = await this.#approvalSteps(
      intent.wallet!,
      intent.offerAsset,
      contract.address as Address,
      offerAmount,
      'intent-sell-amount',
      'offer-amount'
    );
    steps.push({
      id: 'replace-legacy-standard-counter',
      kind: 'protocol',
      contract: contract.address as Address,
      description: `Supersede legacy Standard recipient-bound counterorder ${intent.order.identity.localId}`,
      nativeValue:
        intent.offerAsset.kind === 'native'
          ? offerAmount.toString()
          : '0',
      gasCap:
        intent.offerAsset.kind === 'private-erc20' ||
        intent.requestAsset.kind === 'private-erc20'
          ? PRIVATE_WRITE_GAS_CAP.toString()
          : STANDARD_GAS_CAP.toString(),
      encoding: {
        selector: requireSelector(
          contract,
          'counterTradeAndCloseCounteredTrade'
        ),
        arguments: [
          intent.order.identity.localId,
          assetTuple(intent.offerAsset, offerAmount),
          assetTuple(intent.requestAsset, requestAmount),
          isoToUnixSeconds(intent.expiresAt)
        ]
      }
    });
    return {
      contract,
      steps,
      nativePrincipal:
        intent.offerAsset.kind === 'native' ? offerAmount : 0n,
      feeRequired: true,
      expectedResult:
        'The selected legacy Standard counterorder is declined and replaced atomically by a new legacy Standard recipient-bound counterorder.'
    };
  }

  async #buildEdit(
    intent: Extract<DomainIntent, { action: 'edit' }>
  ): Promise<BuiltPlan> {
    if (intent.order.kind === 'recurring') {
      return this.#buildRecurringEdit(intent);
    }
    const target = intent.order.identity.escrowContract.toLowerCase();
    const standard = requireManifestContract(
      this.#manifest,
      'standardEscrow'
    );
    if (target === standard.address.toLowerCase()) {
      return this.#buildStandardEdit(intent, standard);
    }
    const privateEscrow = requireManifestContract(
      this.#manifest,
      'privateEscrow'
    );
    if (target === privateEscrow.address.toLowerCase()) {
      return this.#buildPrivateLiquidityEdit(intent, privateEscrow);
    }
    const direct = requireManifestContract(this.#manifest, 'directEscrow');
    if (target === direct.address.toLowerCase()) {
      return this.#buildDirectEdit(intent, direct);
    }
    return unsupported(
      'The edited order is not handled by an audited ChainWhisper escrow.'
    );
  }

  async #buildStandardEdit(
    intent: Extract<DomainIntent, { action: 'edit' }>,
    contract: RuntimeContractManifestEntry
  ): Promise<BuiltPlan> {
    if (
      intent.order.legacyCompatibility?.kind ===
      'standard-recipient-bound'
    ) {
      return this.#buildLegacyStandardEdit(intent, contract);
    }
    if (
      intent.order.status !== 'open' ||
      intent.order.access !== 'public' ||
      intent.order.amountVisibility !== 'visible'
    ) {
      return unsupported(
        'Standard edits require an open public order with visible terms.'
      );
    }
    if (intent.wallet!.toLowerCase() !== intent.order.maker.toLowerCase()) {
      return unsupported('Only the order maker can edit this order.');
    }
    const offerDecimal =
      intent.changes.offerAmount ??
      intent.order.remainingOfferAmount ??
      intent.order.offerAmount;
    const requestDecimal =
      intent.changes.requestAmount ??
      intent.order.remainingRequestAmount ??
      intent.order.requestAmount;
    if (!offerDecimal || !requestDecimal || !intent.order.fillPolicy) {
      return unsupported(
        'The trusted order is missing the complete visible terms or fill policy required for replacement.'
      );
    }
    const offerAmount = asAtomic(
      offerDecimal,
      intent.order.offerAsset
    );
    const requestAmount = asAtomic(
      requestDecimal,
      intent.order.requestAsset
    );
    assertUint128(offerAmount, 'Replacement offer amount');
    assertUint128(requestAmount, 'Replacement request amount');
    const policy = intent.order.fillPolicy;
    const nextPolicy = {
      partialFillsAllowed:
        intent.changes.partialFillsAllowed ??
        policy.partialFillsAllowed,
      minPartialFillBps:
        intent.changes.minPartialFillBps ??
        policy.minPartialFillBps,
      minRequestAmount:
        intent.changes.minRequestAmount !== undefined
          ? intent.changes.minRequestAmount
          : policy.minRequestAmount,
      maxRequestAmountPerWallet:
        intent.changes.maxRequestAmountPerWallet !== undefined
          ? intent.changes.maxRequestAmountPerWallet
          : policy.maxRequestAmountPerWallet,
      oneFillPerWallet:
        intent.changes.oneFillPerWallet ??
        policy.oneFillPerWallet
    };
    if (
      nextPolicy.minPartialFillBps < 0 ||
      nextPolicy.minPartialFillBps > 5_000
    ) {
      return unsupported(
        'The replacement partial-fill threshold must be from 0 to 5,000 bps.'
      );
    }
    const expiresAt =
      'expiresAt' in intent.changes
        ? intent.changes.expiresAt ?? null
        : intent.order.expiresAt;
    const steps = await this.#approvalSteps(
      intent.wallet!,
      intent.order.offerAsset,
      contract.address as Address,
      offerAmount,
      'intent-sell-amount'
    );
    steps.push({
      id: 'edit-standard-trade',
      kind: 'protocol',
      contract: contract.address as Address,
      description: `Replace public ChainWhisper order ${intent.order.identity.localId}`,
      nativeValue:
        intent.order.offerAsset.kind === 'native'
          ? offerAmount.toString()
          : '0',
      encoding: {
        selector: requireSelector(contract, 'editTradeWithPolicy'),
        arguments: [
          intent.order.identity.localId,
          assetTuple(intent.order.offerAsset, offerAmount),
          assetTuple(intent.order.requestAsset, requestAmount),
          intent.order.recipient ?? ZERO_ADDRESS,
          isoToUnixSeconds(expiresAt),
          true,
          ZERO_BYTES32,
          [
            nextPolicy.partialFillsAllowed,
            nextPolicy.minPartialFillBps,
            asOptionalAtomic(
              nextPolicy.minRequestAmount,
              intent.order.requestAsset
            ).toString(),
            asOptionalAtomic(
              nextPolicy.maxRequestAmountPerWallet,
              intent.order.requestAsset
            ).toString(),
            nextPolicy.oneFillPerWallet
          ]
        ]
      }
    });
    return {
      contract,
      steps,
      nativePrincipal:
        intent.order.offerAsset.kind === 'native' ? offerAmount : 0n,
      feeRequired: await this.#readChargeFeeOnEdit(contract),
      expectedResult:
        'The original public order is cancelled and replaced with the complete signed terms and fill policy.'
    };
  }

  async #buildLegacyStandardEdit(
    intent: Extract<DomainIntent, { action: 'edit' }>,
    contract: RuntimeContractManifestEntry
  ): Promise<BuiltPlan> {
    const order = intent.order;
    const sourceRelation = order.relation?.kind ?? 'primary';
    if (intent.orderType) {
      return unsupported(
        'Legacy Standard edits cannot be assigned a canonical new-order type.'
      );
    }
    if (
      order.status !== 'open' ||
      order.access !== 'direct' ||
      order.amountVisibility !== 'visible'
    ) {
      return unsupported(
        'Legacy Standard edits require an open recipient-bound order with visible terms.'
      );
    }
    if (sourceRelation === 'counter') {
      return unsupported(
        'Legacy Standard counterorders cannot be edited because editTrade would lose their registered parent relationship. Use chainwhisper_prepare_counter to supersede the counter atomically.'
      );
    }
    if (
      sourceRelation !== 'primary' &&
      sourceRelation !== 'replacement'
    ) {
      return unsupported(
        'The legacy Standard source-order relationship is unsupported for editing.'
      );
    }
    if (intent.wallet!.toLowerCase() !== order.maker.toLowerCase()) {
      return unsupported('Only the order maker can edit this order.');
    }
    if (
      !order.recipient ||
      order.recipient.toLowerCase() === order.maker.toLowerCase()
    ) {
      return unsupported(
        'The legacy Standard order is missing its distinct fixed recipient.'
      );
    }
    const unsupportedChange = Object.entries(intent.changes).some(
      ([key, value]) =>
        value !== undefined &&
        key !== 'offerAmount' &&
        key !== 'requestAmount' &&
        key !== 'expiresAt'
    );
    if (unsupportedChange) {
      return unsupported(
        'Legacy Standard edits can change only the visible offer amount, request amount, or expiry.'
      );
    }
    const originalOffer = order.offerAmount;
    const originalRequest = order.requestAmount;
    const remainingOffer = order.remainingOfferAmount;
    const remainingRequest = order.remainingRequestAmount;
    if (
      !originalOffer ||
      !originalRequest ||
      !remainingOffer ||
      !remainingRequest ||
      !order.fillPolicy
    ) {
      return unsupported(
        'The trusted legacy Standard order is missing complete visible terms or its verified fill policy.'
      );
    }
    if (
      asAtomic(originalOffer, order.offerAsset) !==
        asAtomic(remainingOffer, order.offerAsset) ||
      asAtomic(originalRequest, order.requestAsset) !==
        asAtomic(remainingRequest, order.requestAsset)
    ) {
      return unsupported(
        'Partially filled legacy Standard orders cannot be edited safely.'
      );
    }
    const liveDefaultMinPartialFillBps =
      await this.#readDefaultMinPartialFillBps(contract);
    const policy = order.fillPolicy;
    if (
      policy.partialFillsAllowed !== true ||
      policy.minPartialFillBps !== liveDefaultMinPartialFillBps ||
      asOptionalAtomic(
        policy.minRequestAmount,
        order.requestAsset
      ) !== 0n ||
      asOptionalAtomic(
        policy.maxRequestAmountPerWallet,
        order.requestAsset
      ) !== 0n ||
      policy.oneFillPerWallet !== false
    ) {
      return unsupported(
        'Legacy Standard editTrade would reset this order to a different fill policy. Use a canonical replacement flow instead.'
      );
    }
    const offerAmount = asAtomic(
      intent.changes.offerAmount ?? remainingOffer,
      order.offerAsset
    );
    const requestAmount = asAtomic(
      intent.changes.requestAmount ?? remainingRequest,
      order.requestAsset
    );
    assertUint128(offerAmount, 'Legacy replacement offer amount');
    assertUint128(requestAmount, 'Legacy replacement request amount');
    const expiresAt =
      'expiresAt' in intent.changes
        ? intent.changes.expiresAt ?? null
        : order.expiresAt;
    const steps = await this.#approvalSteps(
      intent.wallet!,
      order.offerAsset,
      contract.address as Address,
      offerAmount,
      'intent-sell-amount',
      'offer-amount'
    );
    steps.push({
      id: 'edit-legacy-standard-trade',
      kind: 'protocol',
      contract: contract.address as Address,
      description: `Replace legacy Standard recipient-bound order ${order.identity.localId} while preserving recipient ${order.recipient}`,
      nativeValue:
        order.offerAsset.kind === 'native'
          ? offerAmount.toString()
          : '0',
      gasCap:
        order.offerAsset.kind === 'private-erc20' ||
        order.requestAsset.kind === 'private-erc20'
          ? PRIVATE_WRITE_GAS_CAP.toString()
          : STANDARD_GAS_CAP.toString(),
      encoding: {
        selector: requireSelector(contract, 'editTrade'),
        arguments: [
          order.identity.localId,
          assetTuple(order.offerAsset, offerAmount),
          assetTuple(order.requestAsset, requestAmount),
          order.recipient,
          isoToUnixSeconds(expiresAt),
          false,
          ZERO_BYTES32
        ]
      }
    });
    return {
      contract,
      steps,
      nativePrincipal:
        order.offerAsset.kind === 'native' ? offerAmount : 0n,
      feeRequired: await this.#readChargeFeeOnEdit(contract),
      expectedResult:
        'The original legacy Standard order is cancelled and replaced with the same fixed recipient, private access mode, visible terms, and verified live default fill policy.'
    };
  }

  async #buildPrivateLiquidityEdit(
    intent: Extract<DomainIntent, { action: 'edit' }>,
    contract: RuntimeContractManifestEntry
  ): Promise<BuiltPlan> {
    if (
      intent.order.status !== 'open' ||
      intent.order.amountVisibility !== 'private' ||
      intent.order.offerAsset.kind !== 'private-erc20'
    ) {
      return unsupported(
        'Private-liquidity replacement requires an open hidden-liquidity order with a private offered token.'
      );
    }
    if (intent.wallet!.toLowerCase() !== intent.order.maker.toLowerCase()) {
      return unsupported('Only the order maker can replace this order.');
    }
    if (intent.changes.replaceConfidentialTerms !== true) {
      return unsupported(
        'Confirm replacement of the complete confidential terms in the local signer.'
      );
    }
    const unlisted = intent.order.access === 'unlisted';
    const recipient =
      intent.order.access === 'direct'
        ? intent.order.recipient
        : null;
    if (intent.order.access === 'direct' && !recipient) {
      return unsupported(
        'The trusted private-liquidity order is missing its fixed recipient.'
      );
    }
    const expiresAt =
      'expiresAt' in intent.changes
        ? intent.changes.expiresAt ?? null
        : intent.order.expiresAt;
    const steps = await this.#approvalSteps(
      intent.wallet!,
      intent.order.offerAsset,
      contract.address as Address,
      0n,
      'signer-elicitation',
      'hidden-offer-amount'
    );
    const values: PlanPrivateArtifactGroup['values'] = [
      artifactValue(
        'hidden-offer-amount',
        'uint256',
        'signer-elicitation',
        intent.order.offerAsset
      ),
      artifactValue(
        'hidden-request-amount',
        'uint256',
        'signer-elicitation',
        intent.order.requestAsset
      ),
      ...(!unlisted
        ? [
            artifactValue(
              'public-offer-term',
              'uint256',
              'signer-elicitation',
              intent.order.offerAsset
            ),
            artifactValue(
              'public-request-term',
              'uint256',
              'signer-elicitation',
              intent.order.requestAsset
            )
          ]
        : []),
      ...(unlisted
        ? [
            artifactValue(
              'order-access-secret',
              'access-secret',
              'generated-local'
            )
          ]
        : [])
    ];
    const outputs: PlanPrivateArtifactGroup['outputs'] = [
      {
        kind: 'itUint256',
        valueId: 'hidden-offer-amount',
        jsonPointer: '/arguments/8'
      },
      {
        kind: 'trade-recovery-v1',
        jsonPointer: '/arguments/11'
      },
      ...(!unlisted
        ? [
            {
              kind: 'uint256' as const,
              valueId: 'public-offer-term',
              jsonPointer: '/arguments/1/2'
            },
            {
              kind: 'uint256' as const,
              valueId: 'public-request-term',
              jsonPointer: '/arguments/2/2'
            }
          ]
        : []),
      ...(unlisted
        ? [
            {
              kind: 'keccak256' as const,
              valueId: 'order-access-secret',
              jsonPointer: '/arguments/6'
            },
            {
              kind: 'terms-hash-v1' as const,
              jsonPointer: '/arguments/7'
            },
            {
              kind: 'itUint256' as const,
              valueId: 'hidden-offer-amount',
              jsonPointer: '/arguments/9'
            },
            {
              kind: 'itUint256' as const,
              valueId: 'hidden-request-amount',
              jsonPointer: '/arguments/10'
            },
            {
              kind: 'itUint256' as const,
              valueId: 'order-access-secret',
              jsonPointer: '/arguments/12'
            },
            {
              kind: 'direct-terms-v1' as const,
              valueId: 'order-access-secret',
              jsonPointer: '/arguments/13'
            }
          ]
        : [])
    ];
    steps.push({
      id: 'replace-private-liquidity',
      kind: 'protocol',
      contract: contract.address as Address,
      description: `Replace ${intent.order.access} private-liquidity order ${intent.order.identity.localId}`,
      nativeValue: '0',
      gasCap: PRIVATE_WRITE_GAS_CAP.toString(),
      encoding: {
        selector: requireSelector(
          contract,
          'cancelAndReplacePrivateOrderWithRecoveryNote'
        ),
        arguments: [
          intent.order.identity.localId,
          assetTuple(intent.order.offerAsset, 0n),
          assetTuple(intent.order.requestAsset, 0n),
          recipient ?? ZERO_ADDRESS,
          isoToUnixSeconds(expiresAt),
          intent.order.access === 'public',
          ZERO_BYTES32,
          ZERO_BYTES32,
          EMPTY_IT_UINT256,
          EMPTY_IT_UINT256,
          EMPTY_IT_UINT256,
          '0x',
          EMPTY_IT_UINT256,
          '0x'
        ]
      },
      privateArtifactGroups: [
        {
          id: 'private-liquidity-edit-artifacts',
          recipe: 'private-liquidity-edit-v1',
          values,
          outputs,
          context: {
            access: intent.order.access,
            maker: intent.wallet,
            recipient: recipient ?? null,
            replacesEscrowContract:
              intent.order.identity.escrowContract,
            replacesTradeId: intent.order.identity.localId,
            expiresAt
          }
        }
      ]
    });
    return {
      contract,
      steps,
      nativePrincipal: 0n,
      feeRequired: true,
      expectedResult:
        'The original private-liquidity order is cancelled and replaced with signer-confirmed confidential terms.'
    };
  }

  async #buildDirectEdit(
    intent: Extract<DomainIntent, { action: 'edit' }>,
    contract: RuntimeContractManifestEntry
  ): Promise<BuiltPlan> {
    if (
      intent.order.status !== 'open' ||
      (
        intent.order.access !== 'unlisted' &&
        intent.order.access !== 'direct'
      )
    ) {
      return unsupported(
        'Direct replacement requires an open unlisted or fixed-recipient Direct order.'
      );
    }
    if (intent.wallet!.toLowerCase() !== intent.order.maker.toLowerCase()) {
      return unsupported('Only the order maker can replace this order.');
    }
    if (intent.changes.replaceConfidentialTerms !== true) {
      return unsupported(
        'Confirm replacement of the complete Direct terms in the local signer.'
      );
    }
    const recipient =
      intent.order.access === 'direct'
        ? intent.order.recipient
        : null;
    if (intent.order.access === 'direct' && !recipient) {
      return unsupported(
        'The trusted Direct order is missing its fixed recipient.'
      );
    }
    const offerPrivate =
      intent.order.offerAsset.kind === 'private-erc20';
    const requestPrivate =
      intent.order.requestAsset.kind === 'private-erc20';
    const offerDecimal =
      intent.changes.offerAmount ??
      intent.order.remainingOfferAmount ??
      intent.order.offerAmount;
    const requestDecimal =
      intent.changes.requestAmount ??
      intent.order.remainingRequestAmount ??
      intent.order.requestAmount;
    if (!offerPrivate && !offerDecimal) {
      return unsupported(
        'Enter the complete resulting public or native offer amount for the Direct replacement.'
      );
    }
    if (!requestPrivate && !requestDecimal) {
      return unsupported(
        'Enter the complete resulting public or native request amount for the Direct replacement.'
      );
    }
    const offerAmount = offerPrivate
      ? 0n
      : asAtomic(offerDecimal!, intent.order.offerAsset);
    const requestAmount = requestPrivate
      ? 0n
      : asAtomic(requestDecimal!, intent.order.requestAsset);
    const offerSource: PlanPrivateArtifactValueSource = offerPrivate
      ? 'signer-elicitation'
      : 'intent-sell-amount';
    const requestSource: PlanPrivateArtifactValueSource = requestPrivate
      ? 'signer-elicitation'
      : 'intent-buy-amount';
    const expiresAt =
      'expiresAt' in intent.changes
        ? intent.changes.expiresAt ?? null
        : intent.order.expiresAt;
    const steps = await this.#approvalSteps(
      intent.wallet!,
      intent.order.offerAsset,
      contract.address as Address,
      offerAmount,
      offerSource,
      'offer-amount'
    );
    const values: PlanPrivateArtifactGroup['values'] = [
      artifactValue(
        'order-access-secret',
        'access-secret',
        'generated-local'
      ),
      artifactValue(
        'offer-amount',
        'uint256',
        offerSource,
        intent.order.offerAsset
      ),
      artifactValue(
        'request-amount',
        'uint256',
        requestSource,
        intent.order.requestAsset
      )
    ];
    const outputs: PlanPrivateArtifactGroup['outputs'] = [
      {
        kind: 'keccak256',
        valueId: 'order-access-secret',
        jsonPointer: '/arguments/8'
      },
      {
        kind: 'terms-hash-v1',
        jsonPointer: '/arguments/9'
      },
      {
        kind: 'itUint256',
        valueId: 'order-access-secret',
        jsonPointer: '/arguments/10'
      },
      {
        kind: 'direct-terms-v1',
        valueId: 'order-access-secret',
        jsonPointer: '/arguments/11'
      },
      ...(offerPrivate
        ? [
            {
              kind: 'itUint256' as const,
              valueId: 'offer-amount',
              jsonPointer: '/arguments/4'
            }
          ]
        : []),
      ...(requestPrivate
        ? [
            {
              kind: 'itUint256' as const,
              valueId: 'request-amount',
              jsonPointer: '/arguments/5'
            }
          ]
        : [])
    ];
    const parent =
      intent.order.relation?.parentOrder ?? null;
    steps.push({
      id: 'replace-direct-trade',
      kind: 'protocol',
      contract: contract.address as Address,
      description: `Replace Direct ChainWhisper order ${intent.order.identity.localId}`,
      nativeValue:
        intent.order.offerAsset.kind === 'native'
          ? offerAmount.toString()
          : '0',
      gasCap: PRIVATE_WRITE_GAS_CAP.toString(),
      encoding: {
        selector: requireSelector(contract, 'editDirectTrade'),
        arguments: [
          intent.order.identity.localId,
          recurringAssetTuple(intent.order.offerAsset),
          recurringAssetTuple(intent.order.requestAsset),
          [
            offerPrivate ? '0' : offerAmount.toString(),
            requestPrivate ? '0' : requestAmount.toString()
          ],
          EMPTY_IT_UINT256,
          EMPTY_IT_UINT256,
          recipient ?? ZERO_ADDRESS,
          isoToUnixSeconds(expiresAt),
          ZERO_BYTES32,
          ZERO_BYTES32,
          EMPTY_IT_UINT256,
          '0x'
        ]
      },
      privateArtifactGroups: [
        {
          id: 'direct-edit-artifacts',
          recipe: 'direct-edit-v1',
          values,
          outputs,
          context: {
            access: intent.order.access,
            maker: intent.wallet,
            recipient: recipient ?? null,
            replacesEscrowContract:
              intent.order.identity.escrowContract,
            replacesTradeId: intent.order.identity.localId,
            parentEscrowContract:
              parent?.escrowContract ?? null,
            parentTradeId: parent?.localId ?? null,
            expiresAt
          }
        }
      ]
    });
    return {
      contract,
      steps,
      nativePrincipal:
        intent.order.offerAsset.kind === 'native' ? offerAmount : 0n,
      feeRequired: true,
      expectedResult:
        'The original Direct order is cancelled and replaced with new signer-bound encrypted terms.'
    };
  }

  async #buildRecurringEdit(
    intent: Extract<DomainIntent, { action: 'edit' }>
  ): Promise<BuiltPlan> {
    const recurring = intent.order.recurring;
    if (
      !recurring ||
      (
        intent.order.status !== 'open' &&
        intent.order.status !== 'paused'
      )
    ) {
      return unsupported(
        'Recurring edits require an active or paused recurring order.'
      );
    }
    if (intent.wallet!.toLowerCase() !== intent.order.maker.toLowerCase()) {
      return unsupported('Only the recurring order maker can edit it.');
    }
    const contract = requireManifestContract(
      this.#manifest,
      'recurringEscrow'
    );
    if (
      intent.order.identity.escrowContract.toLowerCase() !==
      contract.address.toLowerCase()
    ) {
      return unsupported(
        'The recurring order is not handled by the audited recurring escrow.'
      );
    }
    const baseUnit = 10n ** BigInt(recurring.baseAsset.decimals);
    const buyTerms =
      intent.changes.buyPrice !== undefined
        ? [
            baseUnit.toString(),
            asAtomic(
              intent.changes.buyPrice,
              recurring.quoteAsset
            ).toString()
          ]
        : recurring.buyBaseAmount && recurring.buyQuoteAmount
          ? [
              asAtomic(
                recurring.buyBaseAmount,
                recurring.baseAsset
              ).toString(),
              asAtomic(
                recurring.buyQuoteAmount,
                recurring.quoteAsset
              ).toString()
            ]
          : recurring.buyPrice
            ? [
                baseUnit.toString(),
                asAtomic(
                  recurring.buyPrice,
                  recurring.quoteAsset
                ).toString()
              ]
            : null;
    const sellTerms =
      intent.changes.sellPrice !== undefined
        ? [
            baseUnit.toString(),
            asAtomic(
              intent.changes.sellPrice,
              recurring.quoteAsset
            ).toString()
          ]
        : recurring.sellBaseAmount && recurring.sellQuoteAmount
          ? [
              asAtomic(
                recurring.sellBaseAmount,
                recurring.baseAsset
              ).toString(),
              asAtomic(
                recurring.sellQuoteAmount,
                recurring.quoteAsset
              ).toString()
            ]
          : recurring.sellPrice
            ? [
                baseUnit.toString(),
                asAtomic(
                  recurring.sellPrice,
                  recurring.quoteAsset
                ).toString()
              ]
            : null;
    if (!buyTerms || !sellTerms) {
      return unsupported(
        'The trusted recurring order is missing the complete buy and sell price tuples required for editing.'
      );
    }

    const addBase = asOptionalAtomic(
      intent.changes.addSellBaseLiquidity,
      recurring.baseAsset
    );
    const addQuote = asOptionalAtomic(
      intent.changes.addBuyQuoteLiquidity,
      recurring.quoteAsset
    );
    const removeBase = asOptionalAtomic(
      intent.changes.removeSellBaseLiquidity,
      recurring.baseAsset
    );
    const removeQuote = asOptionalAtomic(
      intent.changes.removeBuyQuoteLiquidity,
      recurring.quoteAsset
    );
    if (
      (addBase > 0n && removeBase > 0n) ||
      (addQuote > 0n && removeQuote > 0n)
    ) {
      return unsupported(
        'A recurring edit cannot add and remove the same inventory side in one action.'
      );
    }
    const privateInventory =
      intent.order.amountVisibility === 'private';
    const basePrivate =
      privateInventory &&
      recurring.baseAsset.kind === 'private-erc20';
    const quotePrivate =
      privateInventory &&
      recurring.quoteAsset.kind === 'private-erc20';
    const adjustPrivate =
      intent.changes.adjustPrivateLiquidity === true;
    const addBaseSource: PlanPrivateArtifactValueSource = basePrivate
      ? adjustPrivate
        ? 'signer-elicitation'
        : 'constant-zero'
      : 'recurring-sell-base-liquidity';
    const addQuoteSource: PlanPrivateArtifactValueSource = quotePrivate
      ? adjustPrivate
        ? 'signer-elicitation'
        : 'constant-zero'
      : 'recurring-buy-quote-liquidity';
    const steps = [
      ...(await this.#approvalSteps(
        intent.wallet!,
        recurring.baseAsset,
        contract.address as Address,
        basePrivate ? 0n : addBase,
        addBaseSource,
        'recurring-edit-add-base',
        basePrivate
      )),
      ...(await this.#approvalSteps(
        intent.wallet!,
        recurring.quoteAsset,
        contract.address as Address,
        quotePrivate ? 0n : addQuote,
        addQuoteSource,
        'recurring-edit-add-quote',
        quotePrivate
      ))
    ];
    const values: PlanPrivateArtifactGroup['values'] = [
      ...(basePrivate
        ? [
            artifactValue(
              'recurring-edit-add-base',
              'uint256',
              addBaseSource,
              recurring.baseAsset,
              true
            ),
            artifactValue(
              'recurring-edit-remove-base',
              'uint256',
              adjustPrivate
                ? 'signer-elicitation'
                : 'constant-zero',
              recurring.baseAsset,
              true
            )
          ]
        : []),
      ...(quotePrivate
        ? [
            artifactValue(
              'recurring-edit-add-quote',
              'uint256',
              addQuoteSource,
              recurring.quoteAsset,
              true
            ),
            artifactValue(
              'recurring-edit-remove-quote',
              'uint256',
              adjustPrivate
                ? 'signer-elicitation'
                : 'constant-zero',
              recurring.quoteAsset,
              true
            )
          ]
        : [])
    ];
    const outputs: PlanPrivateArtifactGroup['outputs'] = [
      ...(basePrivate
        ? [
            {
              kind: 'itUint256' as const,
              valueId: 'recurring-edit-add-base',
              jsonPointer: '/arguments/5'
            },
            {
              kind: 'itUint256' as const,
              valueId: 'recurring-edit-remove-base',
              jsonPointer: '/arguments/9'
            }
          ]
        : []),
      ...(quotePrivate
        ? [
            {
              kind: 'itUint256' as const,
              valueId: 'recurring-edit-add-quote',
              jsonPointer: '/arguments/6'
            },
            {
              kind: 'itUint256' as const,
              valueId: 'recurring-edit-remove-quote',
              jsonPointer: '/arguments/10'
            }
          ]
        : [])
    ];
    steps.push({
      id: 'edit-recurring-order',
      kind: 'protocol',
      contract: contract.address as Address,
      description: `Edit recurring ChainWhisper order ${intent.order.identity.localId}`,
      nativeValue: (
        (recurring.baseAsset.kind === 'native' ? addBase : 0n) +
        (recurring.quoteAsset.kind === 'native' ? addQuote : 0n)
      ).toString(),
      gasCap: privateInventory
        ? PRIVATE_WRITE_GAS_CAP.toString()
        : RECURRING_GAS_CAP.toString(),
      encoding: {
        selector: requireSelector(contract, 'editOrder'),
        arguments: [
          intent.order.identity.localId,
          buyTerms,
          sellTerms,
          basePrivate ? '0' : addBase.toString(),
          quotePrivate ? '0' : addQuote.toString(),
          EMPTY_IT_UINT256,
          EMPTY_IT_UINT256,
          basePrivate ? '0' : removeBase.toString(),
          quotePrivate ? '0' : removeQuote.toString(),
          EMPTY_IT_UINT256,
          EMPTY_IT_UINT256
        ]
      },
      ...(values.length
        ? {
            privateArtifactGroups: [
              {
                id: 'recurring-edit-artifacts',
                recipe: 'recurring-edit-v1' as const,
                values,
                outputs,
                context: {
                  adjustPrivateLiquidity: adjustPrivate,
                  mutuallyExclusiveValueIds: [
                    ...(basePrivate
                      ? [
                          'recurring-edit-add-base:recurring-edit-remove-base'
                        ]
                      : []),
                    ...(quotePrivate
                      ? [
                          'recurring-edit-add-quote:recurring-edit-remove-quote'
                        ]
                      : [])
                  ].join(',')
                }
              }
            ]
          }
        : {})
    });
    return {
      contract,
      steps,
      nativePrincipal:
        (recurring.baseAsset.kind === 'native' ? addBase : 0n) +
        (recurring.quoteAsset.kind === 'native' ? addQuote : 0n),
      feeRequired: false,
      expectedResult:
        'The recurring order prices and requested inventory deltas are updated atomically.'
    };
  }

  async #buildOrderUpdate(
    intent: Extract<DomainIntent, { action: 'order_update' }>
  ): Promise<BuiltPlan> {
    const target = intent.order.identity.escrowContract.toLowerCase();
    const contractName = Object.entries(this.#manifest.contracts).find(
      ([name, contract]) =>
        ['standardEscrow', 'privateEscrow', 'directEscrow', 'recurringEscrow'].includes(name) &&
        contract.address.toLowerCase() === target
    )?.[0];
    if (!contractName) {
      return unsupported('The order does not belong to an audited ChainWhisper escrow.');
    }
    const contract = requireManifestContract(this.#manifest, contractName);
    let selectorName: string;
    let args: unknown[];
    if (intent.update === 'cancel') {
      selectorName = contractName === 'recurringEscrow' ? 'cancelOrder' : 'cancelTrade';
      args = [intent.order.identity.localId];
    } else if (
      (intent.update === 'pause' || intent.update === 'resume') &&
      contractName === 'recurringEscrow'
    ) {
      selectorName =
        intent.update === 'pause' ? 'pauseOrder' : 'resumeOrder';
      args = [intent.order.identity.localId];
    } else if (
      intent.update === 'settle_inventory' &&
      contractName === 'recurringEscrow' &&
      intent.order.status === 'cancelled' &&
      intent.wallet?.toLowerCase() === intent.order.maker.toLowerCase()
    ) {
      selectorName = 'settleInventory';
      args = [intent.order.identity.localId];
    } else if (
      intent.update === 'reclaim_expired' &&
      contractName !== 'recurringEscrow'
    ) {
      selectorName = 'reclaimExpiredTrade';
      args = [intent.order.identity.localId];
    } else if (
      intent.update === 'decline' &&
      contractName !== 'recurringEscrow'
    ) {
      selectorName = 'declineTrade';
      args = [intent.order.identity.localId];
    } else if (
      intent.update === 'refresh' &&
      (contractName === 'standardEscrow' || contractName === 'privateEscrow')
    ) {
      selectorName = 'refreshTrade';
      args = [intent.order.identity.localId];
    } else if (
      intent.update === 'extend_expiry' &&
      contractName === 'standardEscrow' &&
      intent.expiresAt
    ) {
      selectorName = 'extendTradeExpiry';
      args = [intent.order.identity.localId, isoToUnixSeconds(intent.expiresAt)];
    } else {
      return unsupported(
        'That lifecycle action is not allowlisted for the deployed order contract.'
      );
    }
    const selector = requireSelector(contract, selectorName);
    return {
      contract,
      steps: [
        {
          id: 'update-order',
          kind: 'protocol',
          contract: contract.address as Address,
          description: `${intent.update.replaceAll('_', ' ')} ChainWhisper order ${intent.order.identity.localId}`,
          nativeValue: '0',
          encoding: { selector, arguments: args }
        }
      ],
      nativePrincipal: 0n,
      feeRequired: false,
      expectedResult: `The order lifecycle action ${intent.update} is applied.`
    };
  }

  async #readDirectCounterTrust(
    parentEscrow: Address,
    directEscrow: Address
  ): Promise<boolean> {
    try {
      const raw = await this.#rpc.request<Hex>('eth_call', [
        {
          to: parentEscrow,
          data: encodeReadCall(
            'trustedDirectCounterEscrow(address)',
            [directEscrow]
          )
        },
        'latest'
      ]);
      return decodeFunctionResult({
        abi: DIRECT_COUNTER_TRUST_ABI,
        functionName: 'trustedDirectCounterEscrow',
        data: raw
      }) as boolean;
    } catch {
      throw new DomainInputError(
        'The parent escrow Direct-counter trust could not be verified.',
        [],
        'provider_error'
      );
    }
  }

  async #readChargeFeeOnEdit(
    contract: RuntimeContractManifestEntry
  ): Promise<boolean> {
    try {
      const raw = await this.#rpc.request<Hex>('eth_call', [
        {
          to: contract.address,
          data: encodeReadCall('chargeFeeOnEdit()')
        },
        'latest'
      ]);
      return decodeFunctionResult({
        abi: EDIT_FEE_ABI,
        functionName: 'chargeFeeOnEdit',
        data: raw
      }) as boolean;
    } catch {
      throw new DomainInputError(
        'The standard escrow edit-fee policy could not be verified.',
        [],
        'provider_error'
      );
    }
  }

  async #readDefaultMinPartialFillBps(
    contract: RuntimeContractManifestEntry
  ): Promise<number> {
    try {
      const raw = await this.#rpc.request<Hex>('eth_call', [
        {
          to: contract.address,
          data: encodeReadCall('defaultMinPartialFillBps()')
        },
        'latest'
      ]);
      return decodeFunctionResult({
        abi: DEFAULT_PARTIAL_FILL_ABI,
        functionName: 'defaultMinPartialFillBps',
        data: raw
      }) as number;
    } catch {
      throw new DomainInputError(
        'The standard escrow default partial-fill policy could not be verified.',
        [],
        'provider_error'
      );
    }
  }

  #manifestAsset(symbol: string): ResolvedAsset {
    const token = this.#manifest.tokens.find(
      (candidate) => candidate.symbol.toLowerCase() === symbol.toLowerCase()
    );
    if (!token) {
      return unsupported(`The verified ${symbol} asset is unavailable.`);
    }
    return {
      id:
        token.kind === 'native'
          ? 'native:coti'
          : token.address!.toLowerCase(),
      kind: token.kind,
      symbol: token.symbol,
      decimals: token.decimals,
      address: token.address?.toLowerCase() as Address | undefined ?? null,
      verified: true
    };
  }

  async #readBridge(
    address: Address,
    abi: ReturnType<typeof parseAbi>,
    functionName: string,
    args: readonly unknown[] = []
  ): Promise<unknown> {
    try {
      const raw = await this.#rpc.request<Hex>('eth_call', [
        {
          to: address,
          data: encodeReadCall(
            `${functionName}(${
              functionName === 'blacklisted' ? 'address' :
              functionName.startsWith('estimate') ? 'uint256' : ''
            })`,
            args
          )
        },
        'latest'
      ]);
      return decodeFunctionResult({
        abi,
        functionName,
        data: raw
      } as never);
    } catch {
      throw new DomainInputError(
        `The live bridge ${functionName} value could not be verified.`,
        [],
        'provider_error'
      );
    }
  }

  async #readBridgeBoolean(
    address: Address,
    functionName: 'paused' | 'isDepositEnabled' | 'blacklisted',
    args: readonly unknown[] = []
  ): Promise<boolean> {
    return (await this.#readBridge(
      address,
      BRIDGE_COMMON_ABI,
      functionName,
      args
    )) as boolean;
  }

  async #readBridgeUint(
    address: Address,
    functionName:
      | 'minDepositAmount'
      | 'maxDepositAmount'
      | 'minWithdrawAmount'
      | 'maxWithdrawAmount'
  ): Promise<bigint> {
    return (await this.#readBridge(
      address,
      BRIDGE_COMMON_ABI,
      functionName
    )) as bigint;
  }

  async #verifyBridgePair(
    pair: PrivacyBridgePairV1,
    contract: RuntimeContractManifestEntry
  ): Promise<void> {
    if (pair.bridgeKind === 'native') {
      const privateToken = (await this.#readBridge(
        contract.address as Address,
        BRIDGE_NATIVE_ABI,
        'privateCoti'
      )) as Address;
      if (
        privateToken.toLowerCase() !== pair.privateTokenAddress.toLowerCase()
      ) {
        return unsupported('The native bridge private token does not match the allowlisted pair.');
      }
      return;
    }
    const [publicToken, privateToken] = await Promise.all([
      this.#readBridge(
        contract.address as Address,
        BRIDGE_ERC20_ABI,
        'token'
      ) as Promise<Address>,
      this.#readBridge(
        contract.address as Address,
        BRIDGE_ERC20_ABI,
        'privateToken'
      ) as Promise<Address>
    ]);
    if (
      publicToken.toLowerCase() !== pair.publicTokenAddress!.toLowerCase() ||
      privateToken.toLowerCase() !== pair.privateTokenAddress.toLowerCase()
    ) {
      return unsupported('The bridge tokens do not match the allowlisted pair.');
    }
  }

  async #readBridgeQuote(
    pair: PrivacyBridgePairV1,
    address: Address,
    direction: 'public-to-private' | 'private-to-public',
    amount: bigint
  ): Promise<{
    fee: bigint;
    cotiOracleTimestamp: bigint;
    tokenOracleTimestamp: bigint;
    blockTimestamp: bigint;
  }> {
    const functionName =
      direction === 'public-to-private'
        ? 'estimateDepositFee'
        : 'estimateWithdrawFee';
    const result = (await this.#readBridge(
      address,
      pair.bridgeKind === 'native'
        ? BRIDGE_NATIVE_ABI
        : BRIDGE_ERC20_ABI,
      functionName,
      [amount]
    )) as readonly bigint[];
    if (pair.bridgeKind === 'native') {
      const [fee, cotiOracleTimestamp, blockTimestamp] = result;
      if (
        fee === undefined ||
        cotiOracleTimestamp === undefined ||
        blockTimestamp === undefined
      ) {
        throw new DomainInputError('The native bridge returned an invalid quote.', [], 'provider_error');
      }
      return {
        fee,
        cotiOracleTimestamp,
        tokenOracleTimestamp: cotiOracleTimestamp,
        blockTimestamp
      };
    }
    const [fee, cotiOracleTimestamp, tokenOracleTimestamp, blockTimestamp] =
      result;
    if (
      fee === undefined ||
      cotiOracleTimestamp === undefined ||
      tokenOracleTimestamp === undefined ||
      blockTimestamp === undefined
    ) {
      throw new DomainInputError('The token bridge returned an invalid quote.', [], 'provider_error');
    }
    return { fee, cotiOracleTimestamp, tokenOracleTimestamp, blockTimestamp };
  }

  async #approvalSteps(
    wallet: Address,
    asset: ResolvedAsset,
    spender: Address,
    amount: bigint,
    amountSource: PlanPrivateArtifactValueSource = 'intent-sell-amount',
    privateValueId?: string,
    allowZero = false
  ): Promise<PlanStep[]> {
    if (asset.kind === 'native') return [];
    if (!asset.address) {
      return unsupported('The token approval route is not supported.');
    }
    if (asset.kind === 'private-erc20') {
      const deferredAmount =
        amountSource === 'signer-elicitation' ||
        amountSource === 'trusted-order-visible-amount';
      if (!deferredAmount && amount <= 0n) {
        return [];
      }
      const valueId =
        privateValueId ??
        `private-allowance-${asset.symbol
          .toLowerCase()
          .replace(/[^a-z0-9]+/gu, '-')}`;
      return [
        {
          id: `approve-${asset.symbol.toLowerCase().replace(/[^a-z0-9]+/gu, '-')}`,
          kind: 'approval',
          approvalScheme: 'coti-private-exact',
          contract: asset.address,
          token: asset.address,
          amount: '0',
          description: `Set the exact signer-confirmed private ${asset.symbol} allowance`,
          nativeValue: '0',
          gasCap: PRIVATE_WRITE_GAS_CAP.toString(),
          encoding: {
            selector: PRIVATE_APPROVE_SELECTOR,
            arguments: [spender, EMPTY_IT_UINT256]
          },
          privateArtifactGroups: [
            {
              id: `private-allowance-${asset.symbol
                .toLowerCase()
                .replace(/[^a-z0-9]+/gu, '-')}`,
              recipe: 'coti-private-exact-allowance-v1',
              values: [
                artifactValue(
                  valueId,
                  'uint256',
                  amountSource,
                  asset,
                  allowZero
                )
              ],
              outputs: [
                {
                  kind: 'coti-private-exact-allowance',
                  valueId,
                  jsonPointer: '/arguments/1'
                }
              ],
              context: {
                token: asset.address,
                targetContract: asset.address,
                functionSelector: PRIVATE_APPROVE_SELECTOR,
                spender,
                accountEncryptionRequired: true
              }
            }
          ]
        }
      ];
    }
    if (amount <= 0n || asset.kind !== 'erc20') return [];
    const allowance = await this.#readAllowance(
      asset.address,
      wallet,
      spender
    );
    if (allowance === amount) return [];
    const approval: PlanStep = {
      id: `approve-${asset.symbol.toLowerCase().replace(/[^a-z0-9]+/gu, '-')}`,
      kind: 'approval',
      contract: asset.address,
      token: asset.address,
      amount: amount.toString(),
      approvalScheme: 'erc20-exact',
      description: `Approve exactly ${amount.toString()} atomic ${asset.symbol}`,
      nativeValue: '0',
      encoding: {
        selector: APPROVE_SELECTOR,
        arguments: [spender, amount.toString()]
      }
    };
    if (allowance === 0n) return [approval];
    return [
      {
        id: `reset-${asset.symbol.toLowerCase().replace(/[^a-z0-9]+/gu, '-')}-allowance`,
        kind: 'approval',
        contract: asset.address,
        token: asset.address,
        amount: '0',
        approvalScheme: 'erc20-reset',
        description: `Reset the existing ${asset.symbol} allowance to zero`,
        nativeValue: '0',
        encoding: {
          selector: APPROVE_SELECTOR,
          arguments: [spender, '0']
        }
      },
      approval
    ];
  }

  async #readAllowance(
    token: Address,
    wallet: Address,
    spender: Address
  ): Promise<bigint> {
    try {
      const data = encodeReadCall('allowance(address,address)', [
        wallet,
        spender
      ]);
      const raw = await this.#rpc.request<Hex>('eth_call', [
        { to: token, data },
        'latest'
      ]);
      return decodeFunctionResult({
        abi: ALLOWANCE_ABI,
        functionName: 'allowance',
        data: raw
      }) as bigint;
    } catch {
      return 0n;
    }
  }

  async #readFee(
    contract: RuntimeContractManifestEntry
  ): Promise<{ amount: bigint; recipient: Address }> {
    try {
      const [amountRaw, recipientRaw] = await Promise.all([
        this.#rpc.request<Hex>('eth_call', [
          {
            to: contract.address,
            data: encodeReadCall('feeAmount()')
          },
          'latest'
        ]),
        this.#rpc.request<Hex>('eth_call', [
          {
            to: contract.address,
            data: encodeReadCall('feeRecipient()')
          },
          'latest'
        ])
      ]);
      const amount = decodeFunctionResult({
        abi: FEE_ABI,
        functionName: 'feeAmount',
        data: amountRaw
      }) as bigint;
      const recipient = decodeFunctionResult({
        abi: FEE_ABI,
        functionName: 'feeRecipient',
        data: recipientRaw
      }) as Address;
      if (
        amount < 0n ||
        !/^0x[a-fA-F0-9]{40}$/u.test(recipient) ||
        recipient.toLowerCase() === ZERO_ADDRESS
      ) {
        throw new Error('invalid-fee-response');
      }
      return { amount, recipient: recipient.toLowerCase() as Address };
    } catch {
      throw new DomainInputError(
        'The live contract fee and recipient could not be verified.',
        [],
        'provider_error'
      );
    }
  }

  async #simulate(
    wallet: Address,
    steps: readonly PlanStep[]
  ): Promise<{
    ok: boolean;
    deferredPrivateArtifacts: boolean;
    blockNumber: string;
    warnings: string[];
    errorCode?: string;
  }> {
    const blockNumber = await this.#rpc
      .request<string>('eth_blockNumber', [])
      .catch(() => 'latest');
    const warnings: string[] = [];
    const hasApproval = steps.some((step) => step.kind === 'approval');
    let deferredPrivateArtifacts = false;
    for (const step of steps) {
      if (step.privateArtifactGroups?.length) {
        deferredPrivateArtifacts = true;
        continue;
      }
      const { data } = encodeAllowlistedPlanStep(this.#manifest, step);
      try {
        await this.#rpc.request<Hex>('eth_call', [
          {
            from: wallet,
            to: step.contract,
            data,
            value: toHex(BigInt(step.nativeValue))
          },
          blockNumber
        ]);
      } catch {
        if (step.kind === 'protocol' && hasApproval) {
          warnings.push(
            'The protocol call is simulated again by the signer after the exact approval confirms.'
          );
          continue;
        }
        try {
          const estimatedGas = BigInt(
            await this.#rpc.request<Hex>('eth_estimateGas', [
              {
                from: wallet,
                to: step.contract,
                data,
                value: toHex(BigInt(step.nativeValue))
              }
            ])
          );
          if (estimatedGas > sumGas([step])) {
            return {
              ok: false,
              deferredPrivateArtifacts,
              blockNumber,
              warnings,
              errorCode: 'ESTIMATED_GAS_CAP_EXCEEDED'
            };
          }
          warnings.push(
            'The RPC rejected eth_call for this write, but its full execution simulation succeeded through eth_estimateGas; the signer independently repeats gas estimation before confirmation and broadcast.'
          );
          continue;
        } catch {
          // Some COTI MPC writes cannot be represented by eth_call even though
          // the node can execute them during gas estimation. Both simulations
          // must fail before preparation is rejected.
        }
        return {
          ok: false,
          deferredPrivateArtifacts,
          blockNumber,
          warnings,
          errorCode: 'ETH_CALL_SIMULATION_FAILED'
        };
      }
    }
    if (deferredPrivateArtifacts) {
      warnings.push(
        'Confidential calldata is simulated by the local signer after it materializes the signed private artifacts.'
      );
    }
    return { ok: true, deferredPrivateArtifacts, blockNumber, warnings };
  }
}

export const encodeUintResultForTest = (value: bigint): Hex =>
  encodeAbiParameters([{ type: 'uint256' }], [value]);
