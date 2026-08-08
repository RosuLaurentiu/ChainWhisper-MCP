import {
  canonicalize,
  sha256Hex,
  type HexString,
} from '../shared/index.js';
import {
  autonomyResumeBinding,
  type ActivationApprovalRequestV1,
  type ActivationApprovalResultV1,
  type ActiveAutonomyPolicyV1,
  type AutonomyLocalApprovalHooks,
  type AutonomyPolicyProposalV1,
} from './autonomy.js';
import { ConfirmationGate } from './confirmation.js';
import { SignerError } from './errors.js';
import type { Address, ConfirmationRequest } from './types.js';
import {
  policyAmountDisplay,
  policyAssetMetadata,
  policyDuration,
  policyPriceDisplay,
} from './autonomyPresentation.js';

const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000' as Address;

const safeId = (prefix: string, hash: string): string =>
  `${prefix}-${hash.slice(2, 18)}`;

const privateAmountAuthority = (
  enabled: boolean,
): string =>
  enabled
    ? 'The agent may both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.'
    : 'The agent may neither choose private amounts nor view policy-scoped private balances, hidden order inventory/progress, or participant receipts under this policy.';

export type AutonomyPolicyResumeDetail = {
  label: string;
  value: string;
};

type PolicyDetail = AutonomyPolicyResumeDetail;

const localTime = (iso: string): string =>
  `${new Date(iso).toLocaleString()} (local time)`;

const amountDisplay = (
  manifestHash: string,
  asset: string,
  amount: string,
): string => {
  const metadata = policyAssetMetadata(manifestHash, asset);
  const display = policyAmountDisplay(amount, metadata);
  return display === undefined
    ? `${amount} atomic units ${asset}`
    : `${display} ${metadata?.symbol ?? asset}`;
};

const amountEditor = (
  manifestHash: string,
  entry: { asset: string; amount: string },
) => {
  const metadata = policyAssetMetadata(manifestHash, entry.asset);
  const displayAmount = policyAmountDisplay(entry.amount, metadata);
  return {
    ...entry,
    ...(metadata
      ? {
          symbol: metadata.symbol,
          decimals: metadata.decimals,
          ...(displayAmount === undefined ? {} : { displayAmount }),
        }
      : {}),
  };
};

const priceBandEditor = (
  manifestHash: string,
  band: Extract<
    AutonomyPolicyProposalV1,
    { mode: 'bounded' }
  >['limits']['priceBands'][number],
) => {
  const sell = policyAssetMetadata(manifestHash, band.sellAsset);
  const buy = policyAssetMetadata(manifestHash, band.buyAsset);
  return {
    sellAsset: band.sellAsset,
    buyAsset: band.buyAsset,
    minimumNumerator: band.minimumBuyPerSellNumerator,
    minimumDenominator: band.minimumBuyPerSellDenominator,
    maximumNumerator: band.maximumBuyPerSellNumerator,
    maximumDenominator: band.maximumBuyPerSellDenominator,
    ...(sell
      ? { sellSymbol: sell.symbol, sellDecimals: sell.decimals }
      : {}),
    ...(buy ? { buySymbol: buy.symbol, buyDecimals: buy.decimals } : {}),
    minimumDisplay: policyPriceDisplay(
      band.minimumBuyPerSellNumerator,
      band.minimumBuyPerSellDenominator,
      sell?.decimals,
      buy?.decimals,
    ),
    maximumDisplay: policyPriceDisplay(
      band.maximumBuyPerSellNumerator,
      band.maximumBuyPerSellDenominator,
      sell?.decimals,
      buy?.decimals,
    ),
  };
};

const boundedScopeDetails = (
  proposal: Extract<AutonomyPolicyProposalV1, { mode: 'bounded' }>,
): PolicyDetail[] => [
  {
    label: 'Allowed actions',
    value: proposal.scope.allowedActions.join(', ') || 'None',
  },
  {
    label: 'Allowed assets',
    value: proposal.scope.allowedAssets.join(', ') || 'None',
  },
  {
    label: 'Allowed pairs',
    value:
      proposal.scope.allowedPairs
        .map(({ sellAsset, buyAsset }) => `${sellAsset} -> ${buyAsset}`)
        .join(', ') || 'None',
  },
  {
    label: 'Allowed order types',
    value: proposal.scope.allowedOrderTypes.join(', ') || 'None',
  },
  {
    label: 'Allowed counterparties',
    value: proposal.scope.allowedCounterparties.join(', ') || 'None',
  },
  {
    label: 'Allowed Privacy Portal routes',
    value:
      proposal.scope.allowedBridgeRoutes
        .map(({ pair, direction }) => `${pair}: ${direction.replaceAll('-', ' ')}`)
        .join(', ') || 'None',
  },
  {
    label: 'Private messaging',
    value: proposal.scope.messaging.enabled
      ? `Enabled only for: ${
          proposal.scope.messaging.counterparties.join(', ') || 'None'
        }`
      : 'Disabled',
  },
];

const policyDetails = (
  proposal: AutonomyPolicyProposalV1,
): PolicyDetail[] => {
  const common = [
    { label: 'Mode', value: proposal.mode },
    { label: 'Starts', value: localTime(proposal.startsAt) },
    { label: 'Expires', value: localTime(proposal.expiresAt) },
    {
      label: 'Duration',
      value: policyDuration(proposal.startsAt, proposal.expiresAt),
    },
    {
      label: 'Private amount choice and policy-scoped state viewing',
      value: privateAmountAuthority(
        proposal.agentVisiblePrivateAmounts,
      ),
    },
    { label: 'Runtime manifest digest', value: proposal.manifestHash },
  ];
  if (proposal.mode === 'full') {
    return [
      ...common,
      {
        label: 'Allowed surface',
        value:
          'Audited ChainWhisper orders, recurring actions, Privacy Portal transactions, and private messaging only',
      },
      {
        label: 'Still forbidden',
        value:
          'Arbitrary calldata/transfers, unknown contracts, administration, wallet replacement, onboarding, token setup, policy changes, and secret deletion',
      },
    ];
  }
  return [
    ...common,
    ...boundedScopeDetails(proposal),
    {
      label: 'Per-action asset budgets',
      value:
        proposal.limits.perActionSpend
          .map(({ asset, amount }) =>
            amountDisplay(proposal.manifestHash, asset, amount),
          )
          .join(', ') || 'None',
    },
    {
      label: 'Cumulative asset budgets',
      value:
        proposal.limits.cumulativeSpend
          .map(({ asset, amount }) =>
            amountDisplay(proposal.manifestHash, asset, amount),
          )
          .join(', ') || 'None',
    },
    {
      label: 'Allowed price bands',
      value:
        proposal.limits.priceBands
          .map((band) => {
            const display = priceBandEditor(proposal.manifestHash, band);
            const unit =
              display.sellSymbol && display.buySymbol
                ? `${display.buySymbol} per ${display.sellSymbol}`
                : `atomic ${band.buyAsset} per atomic ${band.sellAsset}`;
            return `${display.minimumDisplay ?? 'Unavailable'} – ${
              display.maximumDisplay ?? 'Unavailable'
            } ${unit}`;
          })
          .join(', ') || 'None',
    },
    {
      label: 'Maximum actions / messages',
      value: `${proposal.limits.maximumActions} / ${proposal.limits.maximumMessages}`,
    },
    {
      label: 'Maximum native value',
      value: `${amountDisplay(
        proposal.manifestHash,
        'native',
        proposal.limits.maximumNativeValuePerAction,
      )} per action; ${amountDisplay(
        proposal.manifestHash,
        'native',
        proposal.limits.maximumNativeValueCumulative,
      )} cumulative`,
    },
    {
      label: 'Maximum network fees',
      value: `${amountDisplay(
        proposal.manifestHash,
        'native',
        proposal.limits.maximumNetworkFeePerAction,
      )} per action; ${amountDisplay(
        proposal.manifestHash,
        'native',
        proposal.limits.maximumNetworkFeeCumulative,
      )} cumulative`,
    },
    {
      label: 'Exact atomic per-action budgets',
      value:
        proposal.limits.perActionSpend
          .map(({ asset, amount }) => `${amount} ${asset}`)
          .join(', ') || 'None',
    },
    {
      label: 'Exact atomic cumulative budgets',
      value:
        proposal.limits.cumulativeSpend
          .map(({ asset, amount }) => `${amount} ${asset}`)
          .join(', ') || 'None',
    },
    {
      label: 'Exact atomic network fee limits',
      value: `${proposal.limits.maximumNetworkFeePerAction} wei per action; ${proposal.limits.maximumNetworkFeeCumulative} wei cumulative`,
    },
    {
      label: 'Exact atomic price bands',
      value:
        proposal.limits.priceBands
          .map(
            (band) =>
              `${band.minimumBuyPerSellNumerator}/${band.minimumBuyPerSellDenominator} – ${band.maximumBuyPerSellNumerator}/${band.maximumBuyPerSellDenominator} atomic ${band.buyAsset} per atomic ${band.sellAsset}`,
          )
          .join(', ') || 'None',
    },
  ];
};

const confirmationForPolicy = (
  proposal: AutonomyPolicyProposalV1,
): ConfirmationRequest => {
  const operationHash = sha256Hex(
    canonicalize({
      domain: 'chainwhisper/autonomy-activation/1',
      proposal,
    }),
  );
  return {
    operationId: safeId('autonomy', operationHash),
    operationHash,
    stepId: 'activate-autonomy-policy',
    stepIndex: 0,
    stepCount: 1,
    wallet: proposal.wallet.toLowerCase() as Address,
    contract: ZERO_ADDRESS,
    action:
      proposal.mode === 'full'
        ? 'activate_full_autonomy'
        : 'activate_bounded_autonomy',
    orderType: null,
    orderTypeLabel:
      proposal.mode === 'full'
        ? '24-hour audited economic surface'
        : 'User-bounded policy',
    assets:
      proposal.mode === 'bounded' ? [...proposal.scope.allowedAssets] : [],
    amounts:
      proposal.mode === 'bounded'
        ? proposal.limits.cumulativeSpend.map(
            ({ asset, amount }) =>
              amountDisplay(proposal.manifestHash, asset, amount),
          )
        : [],
    details: policyDetails(proposal),
    counterparty: null,
    spender: null,
    fee: 'No transaction or protocol fee',
    nativeValue: '0',
    gasCap: '0',
    expectedResult:
      `The signer stores a wallet-bound local autonomy policy. Every later action must still match the audited runtime and the exact policy. ${privateAmountAuthority(proposal.agentVisiblePrivateAmounts)}`,
    summary:
      proposal.mode === 'full'
        ? `Allow this dedicated Agent Wallet to perform all audited ChainWhisper economic actions for no more than 24 hours. ${privateAmountAuthority(proposal.agentVisiblePrivateAmounts)}`
        : `Allow only the displayed actions, assets, pairs, counterparties, limits, and duration. ${privateAmountAuthority(proposal.agentVisiblePrivateAmounts)}`,
    authorizationScope: 'complete-logical-action',
    actionButtonLabel:
      proposal.mode === 'full'
        ? 'Activate 24-hour full autonomy'
        : 'Activate bounded autonomy',
    maximumNetworkFeeWei: '0',
    maximumNetworkFeeCoti: '0',
    autonomyEditor: {
      startsAt: proposal.startsAt,
      expiresAt: proposal.expiresAt,
      duration: policyDuration(proposal.startsAt, proposal.expiresAt),
      agentVisiblePrivateAmounts:
        proposal.agentVisiblePrivateAmounts,
      perActionSpend:
        proposal.mode === 'bounded'
          ? proposal.limits.perActionSpend.map((entry) =>
              amountEditor(proposal.manifestHash, entry),
            )
          : [],
      cumulativeSpend:
        proposal.mode === 'bounded'
          ? proposal.limits.cumulativeSpend.map((entry) =>
              amountEditor(proposal.manifestHash, entry),
            )
          : [],
      ...(proposal.mode === 'bounded'
        ? {
            maximumNativeValuePerAction:
              proposal.limits.maximumNativeValuePerAction,
            maximumNativeValueCumulative:
              proposal.limits.maximumNativeValueCumulative,
            maximumNetworkFeePerAction:
              proposal.limits.maximumNetworkFeePerAction,
            maximumNetworkFeeCumulative:
              proposal.limits.maximumNetworkFeeCumulative,
            maximumActions: proposal.limits.maximumActions,
            maximumMessages: proposal.limits.maximumMessages,
            priceBands: proposal.limits.priceBands.map((band) =>
              priceBandEditor(proposal.manifestHash, band),
            ),
          }
        : { priceBands: [] }),
    },
    ...(proposal.mode === 'full'
      ? {
          acknowledgements: [
            'I am using a dedicated, minimally funded Agent Wallet and understand the beta trusts this local host.',
            'I understand full autonomy covers only the audited ChainWhisper economic surface and lasts no more than 24 hours. If agentVisiblePrivateAmounts remains enabled, the agent may both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.',
          ],
        }
      : {}),
  };
};

const editedProposal = (
  proposal: AutonomyPolicyProposalV1,
  values: Readonly<Record<string, string>>,
): AutonomyPolicyProposalV1 => {
  const candidate = structuredClone(proposal);
  if (values['autonomy.expiresAt']) {
    candidate.expiresAt = values['autonomy.expiresAt'];
  }
  candidate.agentVisiblePrivateAmounts =
    values['autonomy.agentVisiblePrivateAmounts'] === 'true';
  if (candidate.mode !== 'bounded') return candidate;
  candidate.limits.perActionSpend.forEach((entry, index) => {
    entry.amount =
      values[`autonomy.perAction.${index}`] ?? entry.amount;
  });
  candidate.limits.cumulativeSpend.forEach((entry, index) => {
    entry.amount =
      values[`autonomy.cumulative.${index}`] ?? entry.amount;
  });
  candidate.limits.maximumNativeValuePerAction =
    values['autonomy.maximumNativeValuePerAction'] ??
    candidate.limits.maximumNativeValuePerAction;
  candidate.limits.maximumNativeValueCumulative =
    values['autonomy.maximumNativeValueCumulative'] ??
    candidate.limits.maximumNativeValueCumulative;
  candidate.limits.maximumNetworkFeePerAction =
    values['autonomy.maximumNetworkFeePerAction'] ??
    candidate.limits.maximumNetworkFeePerAction;
  candidate.limits.maximumNetworkFeeCumulative =
    values['autonomy.maximumNetworkFeeCumulative'] ??
    candidate.limits.maximumNetworkFeeCumulative;
  candidate.limits.maximumActions = Number(
    values['autonomy.maximumActions'] ??
      candidate.limits.maximumActions,
  );
  candidate.limits.maximumMessages = Number(
    values['autonomy.maximumMessages'] ??
      candidate.limits.maximumMessages,
  );
  candidate.limits.priceBands.forEach((band, index) => {
    band.minimumBuyPerSellNumerator =
      values[`autonomy.price.${index}.minNumerator`] ??
      band.minimumBuyPerSellNumerator;
    band.minimumBuyPerSellDenominator =
      values[`autonomy.price.${index}.minDenominator`] ??
      band.minimumBuyPerSellDenominator;
    band.maximumBuyPerSellNumerator =
      values[`autonomy.price.${index}.maxNumerator`] ??
      band.maximumBuyPerSellNumerator;
    band.maximumBuyPerSellDenominator =
      values[`autonomy.price.${index}.maxDenominator`] ??
      band.maximumBuyPerSellDenominator;
  });
  return candidate;
};

export const autonomyPolicyResumeDetails = (
  policy: ActiveAutonomyPolicyV1,
): AutonomyPolicyResumeDetail[] => [
  { label: 'Policy id', value: policy.id },
  { label: 'Policy mode', value: policy.mode },
  { label: 'Expires', value: localTime(policy.expiresAt) },
  {
    label: 'Private amount choice and policy-scoped state viewing',
    value: privateAmountAuthority(policy.agentVisiblePrivateAmounts),
  },
  ...(policy.mode === 'bounded'
    ? boundedScopeDetails(policy)
    : [
        {
          label: 'Allowed surface',
          value:
            'Audited ChainWhisper orders, recurring actions, Privacy Portal transactions, and private messaging only',
        },
        {
          label: 'Still forbidden',
          value:
            'Arbitrary calldata/transfers, unknown contracts, administration, wallet replacement, onboarding, token setup, policy changes, and secret deletion',
        },
      ]),
  { label: 'Exact terms digest', value: policy.termsDigest },
];

const lifecycleConfirmation = (
  action: 'resume' | 'revoke',
  policy: ActiveAutonomyPolicyV1,
): ConfirmationRequest => {
  const operationHash = sha256Hex(
    canonicalize({
      domain: `chainwhisper/autonomy-${action}/1`,
      policyId: policy.id,
      termsDigest: policy.termsDigest,
    }),
  );
  return {
    operationId: safeId(`autonomy-${action}`, operationHash),
    operationHash,
    stepId: `${action}-autonomy-policy`,
    stepIndex: 0,
    stepCount: 1,
    wallet: policy.wallet.toLowerCase() as Address,
    contract: ZERO_ADDRESS,
    action: action === 'resume' ? 'resume_autonomy' : 'revoke_autonomy',
    orderType: null,
    orderTypeLabel: `${policy.mode} autonomy policy`,
    assets: [],
    amounts: [],
    details: autonomyPolicyResumeDetails(policy),
    counterparty: null,
    spender: null,
    fee: 'No transaction or protocol fee',
    nativeValue: '0',
    gasCap: '0',
    expectedResult:
      action === 'resume'
        ? `Matching autonomous actions may continue under the unchanged policy. ${privateAmountAuthority(policy.agentVisiblePrivateAmounts)}`
        : `The policy is permanently revoked. Pending signed transactions remain reserved for recovery. ${
            policy.agentVisiblePrivateAmounts
              ? 'Revocation also removes the policy authority that let the agent both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.'
              : privateAmountAuthority(false)
          }`,
    summary:
      action === 'resume'
        ? `Resume the unchanged local autonomy policy. ${privateAmountAuthority(policy.agentVisiblePrivateAmounts)}`
        : `Permanently revoke this local autonomy policy. ${
            policy.agentVisiblePrivateAmounts
              ? 'This removes the agent authority to both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.'
              : privateAmountAuthority(false)
          }`,
    authorizationScope: 'complete-logical-action',
    actionButtonLabel:
      action === 'resume' ? 'Resume autonomy' : 'Revoke policy',
    maximumNetworkFeeWei: '0',
    maximumNetworkFeeCoti: '0',
  };
};

const resumeConfirmation = (
  policies: readonly ActiveAutonomyPolicyV1[],
): ConfirmationRequest | null => {
  const first = policies[0];
  if (!first) return null;
  const operationHash = autonomyResumeBinding(policies);
  if (policies.length === 1) {
    return {
      ...lifecycleConfirmation('resume', first),
      operationId: safeId('autonomy-resume', operationHash),
      operationHash,
    };
  }
  const count = policies.length;
  return {
    ...lifecycleConfirmation('resume', first),
    operationId: safeId('autonomy-resume', operationHash),
    operationHash,
    stepId: 'resume-autonomy-policies',
    orderTypeLabel: `${count} autonomy policies`,
    details: [
      { label: 'Policies affected', value: String(count) },
      ...policies.flatMap((policy, index) =>
        autonomyPolicyResumeDetails(policy).map(({ label, value }) => ({
          label: `Policy ${index + 1} · ${label}`,
          value,
        })),
      ),
    ],
    expectedResult:
      `Matching autonomous actions may continue under all ${count} displayed unchanged policies. Private amount choice and policy-scoped state viewing authority is disclosed separately for every policy.`,
    summary:
      `Resume ${count} policies under their unchanged terms. Every affected policy is identified by its exact policy id and terms digest below.`,
    actionButtonLabel: `Resume ${count} policies`,
  };
};

const declined = (error: unknown): boolean =>
  error instanceof SignerError &&
  ['CONFIRMATION_DECLINED', 'CONFIRMATION_TIMEOUT'].includes(error.code);

export class ControlPageAutonomyApprovals
  implements AutonomyLocalApprovalHooks
{
  readonly #confirmation: ConfirmationGate;
  #resumePreapprovedBinding: HexString | null = null;
  #revocationPreapprovedPolicyId: string | null = null;

  constructor(confirmation: ConfirmationGate) {
    this.#confirmation = confirmation;
  }

  preapproveNextResumeFromControlPage(binding?: HexString): () => void {
    if (!binding) {
      this.#resumePreapprovedBinding = null;
      return () => undefined;
    }
    this.#resumePreapprovedBinding = binding;
    return () => {
      if (this.#resumePreapprovedBinding === binding) {
        this.#resumePreapprovedBinding = null;
      }
    };
  }

  preapproveNextRevocationFromControlPage(policyId: string): void {
    this.#revocationPreapprovedPolicyId = policyId;
  }

  async approveActivation(
    request: ActivationApprovalRequestV1,
  ): Promise<ActivationApprovalResultV1> {
    try {
      const values = await this.#confirmation.confirm(
        confirmationForPolicy(request.proposal),
      );
      return {
        approved: true,
        proposal: editedProposal(request.proposal, values),
      };
    } catch (error) {
      if (declined(error)) return { approved: false };
      throw error;
    }
  }

  async approveResume(request: {
    policies: ActiveAutonomyPolicyV1[];
  }): Promise<boolean> {
    if (this.#resumePreapprovedBinding !== null) {
      const preapprovedBinding = this.#resumePreapprovedBinding;
      this.#resumePreapprovedBinding = null;
      return preapprovedBinding === autonomyResumeBinding(request.policies);
    }
    const confirmation = resumeConfirmation(request.policies);
    if (!confirmation) return false;
    try {
      await this.#confirmation.confirm(confirmation);
      return true;
    } catch (error) {
      if (declined(error)) return false;
      throw error;
    }
  }

  async approveRevocation(request: {
    policy: ActiveAutonomyPolicyV1;
  }): Promise<boolean> {
    if (this.#revocationPreapprovedPolicyId === request.policy.id) {
      this.#revocationPreapprovedPolicyId = null;
      return true;
    }
    try {
      await this.#confirmation.confirm(
        lifecycleConfirmation('revoke', request.policy),
      );
      return true;
    } catch (error) {
      if (declined(error)) return false;
      throw error;
    }
  }
}
