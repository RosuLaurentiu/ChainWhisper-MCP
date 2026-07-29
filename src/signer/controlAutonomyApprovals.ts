import { canonicalize, sha256Hex } from '../shared/index.js';
import type {
  ActivationApprovalRequestV1,
  ActivationApprovalResultV1,
  ActiveAutonomyPolicyV1,
  AutonomyLocalApprovalHooks,
  AutonomyPolicyProposalV1,
} from './autonomy.js';
import { ConfirmationGate } from './confirmation.js';
import { SignerError } from './errors.js';
import type { Address, ConfirmationRequest } from './types.js';

const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000' as Address;

const safeId = (prefix: string, hash: string): string =>
  `${prefix}-${hash.slice(2, 18)}`;

const policyDetails = (
  proposal: AutonomyPolicyProposalV1,
): Array<{ label: string; value: string }> => {
  const common = [
    { label: 'Mode', value: proposal.mode },
    { label: 'Starts', value: proposal.startsAt },
    { label: 'Expires', value: proposal.expiresAt },
    {
      label: 'Agent-visible private amounts',
      value: proposal.agentVisiblePrivateAmounts ? 'Allowed' : 'Not allowed',
    },
    { label: 'Runtime manifest', value: proposal.manifestHash },
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
    {
      label: 'Allowed actions',
      value: proposal.scope.allowedActions.join(', ') || 'None',
    },
    {
      label: 'Allowed assets',
      value: proposal.scope.allowedAssets.join(', ') || 'None',
    },
    {
      label: 'Allowed order types',
      value: proposal.scope.allowedOrderTypes.join(', ') || 'None',
    },
    {
      label: 'Maximum actions / messages',
      value: `${proposal.limits.maximumActions} / ${proposal.limits.maximumMessages}`,
    },
    {
      label: 'Maximum network fees',
      value: `${proposal.limits.maximumNetworkFeePerAction} wei per action; ${proposal.limits.maximumNetworkFeeCumulative} wei cumulative`,
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
            ({ asset, amount }) => `${amount} base units ${asset}`,
          )
        : [],
    details: policyDetails(proposal),
    counterparty: null,
    spender: null,
    fee: 'No transaction or protocol fee',
    nativeValue: '0',
    gasCap: '0',
    expectedResult:
      'The signer stores a wallet-bound local autonomy policy. Every later action must still match the audited runtime and the exact policy.',
    summary:
      proposal.mode === 'full'
        ? 'Allow this dedicated Agent Wallet to perform all audited ChainWhisper economic actions for no more than 24 hours.'
        : 'Allow only the displayed actions, assets, pairs, counterparties, limits, and duration.',
    authorizationScope: 'complete-logical-action',
    actionButtonLabel:
      proposal.mode === 'full'
        ? 'Activate 24-hour full autonomy'
        : 'Activate bounded autonomy',
    maximumNetworkFeeWei: '0',
    maximumNetworkFeeCoti: '0',
    autonomyEditor: {
      expiresAt: proposal.expiresAt,
      agentVisiblePrivateAmounts:
        proposal.agentVisiblePrivateAmounts,
      perActionSpend:
        proposal.mode === 'bounded'
          ? proposal.limits.perActionSpend.map((entry) => ({ ...entry }))
          : [],
      cumulativeSpend:
        proposal.mode === 'bounded'
          ? proposal.limits.cumulativeSpend.map((entry) => ({ ...entry }))
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
            priceBands: proposal.limits.priceBands.map((band) => ({
              sellAsset: band.sellAsset,
              buyAsset: band.buyAsset,
              minimumNumerator:
                band.minimumBuyPerSellNumerator,
              minimumDenominator:
                band.minimumBuyPerSellDenominator,
              maximumNumerator:
                band.maximumBuyPerSellNumerator,
              maximumDenominator:
                band.maximumBuyPerSellDenominator,
            })),
          }
        : { priceBands: [] }),
    },
    ...(proposal.mode === 'full'
      ? {
          acknowledgements: [
            'I am using a dedicated, minimally funded Agent Wallet and understand the beta trusts this local host.',
            'I understand full autonomy covers only the audited ChainWhisper economic surface and lasts no more than 24 hours.',
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
    details: [
      { label: 'Policy id', value: policy.id },
      { label: 'Policy mode', value: policy.mode },
      { label: 'Expires', value: policy.expiresAt },
      { label: 'Exact terms digest', value: policy.termsDigest },
    ],
    counterparty: null,
    spender: null,
    fee: 'No transaction or protocol fee',
    nativeValue: '0',
    gasCap: '0',
    expectedResult:
      action === 'resume'
        ? 'Matching autonomous actions may continue under the unchanged policy.'
        : 'The policy is permanently revoked. Pending signed transactions remain reserved for recovery.',
    summary:
      action === 'resume'
        ? 'Resume the unchanged local autonomy policy.'
        : 'Permanently revoke this local autonomy policy.',
    authorizationScope: 'complete-logical-action',
    actionButtonLabel:
      action === 'resume' ? 'Resume autonomy' : 'Revoke policy',
    maximumNetworkFeeWei: '0',
    maximumNetworkFeeCoti: '0',
  };
};

const declined = (error: unknown): boolean =>
  error instanceof SignerError &&
  ['CONFIRMATION_DECLINED', 'CONFIRMATION_TIMEOUT'].includes(error.code);

export class ControlPageAutonomyApprovals
  implements AutonomyLocalApprovalHooks
{
  readonly #confirmation: ConfirmationGate;
  #resumePreapproved = false;
  #revocationPreapprovedPolicyId: string | null = null;

  constructor(confirmation: ConfirmationGate) {
    this.#confirmation = confirmation;
  }

  preapproveNextResumeFromControlPage(): void {
    this.#resumePreapproved = true;
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
    if (this.#resumePreapproved) {
      this.#resumePreapproved = false;
      return true;
    }
    const policy = request.policies.at(-1);
    if (!policy) return false;
    try {
      await this.#confirmation.confirm(
        lifecycleConfirmation('resume', policy),
      );
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
