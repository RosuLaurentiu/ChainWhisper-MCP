import type {
  ConfirmationRequest,
  PrivateValueRequest,
} from './types.js';
import {
  localDateTimeValue,
  policyAmountDisplay,
} from './autonomyPresentation.js';

export type AgentControlOperation = {
  label: string;
  status: string;
  transactionUrl?: string;
  operationId?: string;
  operationHash?: string;
  recoverable?: boolean;
  discardable?: boolean;
  setupAssets?: string[];
};

export type AgentControlSummary = {
  wallet?: string | null;
  network?: string;
  balance?: string;
  privacyStatus?: 'ready' | 'onboarding-required' | 'unknown';
  signerStatus?: 'ready' | 'setup-required' | 'read-only' | 'unavailable';
  autonomy?: {
    mode: 'manual' | 'bounded' | 'full';
    state?: 'active' | 'paused' | 'expired' | 'revoked';
    expiresAt?: string;
    agentVisiblePrivateAmounts?: boolean;
    remainingBudgets?: Array<{ label: string; value: string }>;
  };
  pendingOperations?: number;
  recentOperations?: AgentControlOperation[];
  diagnostics?: Array<{ label: string; value: string }>;
  walletSetup?: {
    required: boolean;
    environmentFilePath: string;
    restartRequired?: boolean;
    replacementBlockedReason?: string;
    generatedBackup?: {
      address: string;
      privateKey: string;
    };
  };
  controlActions?: {
    pause?: boolean;
    resume?: boolean;
    revoke?: boolean;
    onboardPrivacy?: boolean;
    enablePrivateToken?: boolean;
  };
};

export type AgentControlPendingPrompt =
  | {
      id: string;
      kind: 'confirmation';
      request: ConfirmationRequest;
    }
  | {
      id: string;
      kind: 'private-values';
      request: PrivateValueRequest;
    };

export type AgentControlPageModel = {
  csrfToken: string;
  pending: AgentControlPendingPrompt | null;
  summary: AgentControlSummary;
  flash?: string;
  error?: string;
};

export const agentControlStateKey = (
  model: Pick<AgentControlPageModel, 'pending' | 'summary'>,
): string =>
  JSON.stringify({
    pending: model.pending
      ? [model.pending.id, model.pending.kind]
      : null,
    signer: model.summary.signerStatus ?? null,
    privacy: model.summary.privacyStatus ?? null,
    autonomy: model.summary.autonomy
      ? [
          model.summary.autonomy.mode,
          model.summary.autonomy.state ?? null,
          model.summary.autonomy.expiresAt ?? null,
          model.summary.autonomy.agentVisiblePrivateAmounts ?? null,
        ]
      : null,
    pendingOperations: model.summary.pendingOperations ?? 0,
    recent: (model.summary.recentOperations ?? []).map(
      ({
        label,
        status,
        operationId,
        operationHash,
        recoverable,
        discardable,
        setupAssets,
      }) => [
        label,
        status,
        operationId ?? null,
        operationHash ?? null,
        Boolean(recoverable),
        Boolean(discardable),
        setupAssets ?? [],
      ],
    ),
    localActions: model.summary.controlActions
      ? [Boolean(model.summary.controlActions.enablePrivateToken)]
      : null,
    walletSetup: model.summary.walletSetup
      ? [
          model.summary.walletSetup.required,
          Boolean(model.summary.walletSetup.restartRequired),
          Boolean(model.summary.walletSetup.generatedBackup),
        ]
      : null,
  });

const escapeHtml = (value: string): string =>
  value.replace(
    /[&<>"']/gu,
    (character) =>
      ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      })[character] ?? character,
  );

const displayValue = (value: string | null | undefined): string =>
  value && value.trim().length > 0 ? value : 'Not available';

const shortAddress = (value: string | null | undefined): string => {
  if (!value) return 'Not configured';
  return value.length > 18
    ? `${value.slice(0, 10)}…${value.slice(-6)}`
    : value;
};

const humanize = (value: string): string =>
  value
    .replace(/[_-]+/gu, ' ')
    .replace(/\b\w/gu, (character) => character.toUpperCase());

const actionPresentation = (
  action: string,
): { title: string; button: string } => {
  const known: Record<string, { title: string; button: string }> = {
    create_trade: {
      title: 'Create ChainWhisper order',
      button: 'Confirm complete order creation',
    },
    create_recurring: {
      title: 'Create recurring order',
      button: 'Confirm complete order creation',
    },
    fill: {
      title: 'Fill ChainWhisper order',
      button: 'Confirm complete order fill',
    },
    counter: {
      title: 'Create counter-order',
      button: 'Confirm complete counter-order',
    },
    edit: {
      title: 'Edit ChainWhisper order',
      button: 'Confirm complete order edit',
    },
    order_update: {
      title: 'Update ChainWhisper order',
      button: 'Confirm complete order update',
    },
    privacy_bridge: {
      title: 'Use the Privacy Portal',
      button: 'Confirm complete bridge action',
    },
    onboard_privacy: {
      title: 'Enable private trading',
      button: 'Confirm private trading setup',
    },
    enable_private_token: {
      title: 'Prepare private token',
      button: 'Confirm token preparation',
    },
    send_order_message: {
      title: 'Send private order message',
      button: 'Confirm message',
    },
    activate_bounded_autonomy: {
      title: 'Enable bounded autonomy',
      button: 'Activate bounded autonomy',
    },
    activate_full_autonomy: {
      title: 'Enable 24-hour full autonomy',
      button: 'Activate full autonomy',
    },
    resume_autonomy: {
      title: 'Resume agent autonomy',
      button: 'Resume autonomy',
    },
    revoke_autonomy: {
      title: 'Revoke autonomy policy',
      button: 'Revoke policy',
    },
  };
  return (
    known[action] ?? {
      title: humanize(action),
      button: `Confirm ${humanize(action).toLowerCase()}`,
    }
  );
};

const privacyLabel = (request: ConfirmationRequest): string => {
  if (request.action === 'privacy_bridge') return 'Privacy Portal';
  if (request.orderType?.cadence === 'recurring' &&
      request.orderType.termsVisibility === 'hidden-liquidity') {
    return 'Private inventory · public prices';
  }
  if (
    request.orderType?.termsVisibility === 'hidden-liquidity' ||
    request.orderType?.termsVisibility === 'direct-private-terms' ||
    request.action === 'send_order_message' ||
    request.action === 'onboard_privacy' ||
    request.action === 'enable_private_token'
  ) {
    return 'Privacy-protected';
  }
  return 'Public terms';
};

const renderSummaryRows = (
  rows: Array<{ label: string; value: string }>,
): string =>
  rows
    .map(
      ({ label, value }) => `<div class="summary-row">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(value)}</strong>
      </div>`,
    )
    .join('');

const isTechnicalRow = (label: string): boolean =>
  /(?:allowance|approval|reset|native value|gas|contract|selector|calldata|digest|operation hash|step identifier|attestation|exact atomic)/iu.test(
    label,
  );

const recurringExposureRows = (
  rows: Array<{ label: string; value: string }>,
  fullyPrivate: boolean,
): Array<{ label: string; value: string }> => {
  const find = (pattern: RegExp) =>
    rows.find(({ label }) => pattern.test(label.toLowerCase()));
  const sell =
    find(/private (?:send|inventory)/u) ??
    find(/sell-side (?:liquidity|inventory)/u) ??
    find(/you send/u);
  const buy =
    find(/private receive/u) ??
    find(/buy-side (?:liquidity|budget)/u) ??
    find(/you receive/u);
  return [
    ...(sell
      ? [{
          label: sell.label.toLowerCase().includes('encrypted on-chain') ||
            fullyPrivate
            ? 'Sell-side inventory · encrypted on-chain'
            : sell.label.toLowerCase().includes('public on-chain')
              ? 'Sell-side inventory · public on-chain'
              : 'Sell-side inventory',
          value: sell.value,
        }]
      : []),
    ...(buy
      ? [{
          label: buy.label.toLowerCase().includes('encrypted on-chain') ||
            fullyPrivate
            ? 'Buy-side budget · encrypted on-chain'
            : buy.label.toLowerCase().includes('public on-chain')
              ? 'Buy-side budget · public on-chain'
              : 'Buy-side budget',
          value: buy.value,
        }]
      : []),
  ];
};

const renderAutonomyEditor = (
  request: ConfirmationRequest,
): string => {
  const editor = request.autonomyEditor;
  if (!editor) return '';
  const amountFields = (
    title: string,
    prefix: 'perAction' | 'cumulative',
    entries: typeof editor.perActionSpend,
  ): string =>
    entries.length
      ? `<fieldset class="policy-fields"><legend>${escapeHtml(title)}</legend>${entries
          .map(
            (entry, index) => {
              const human =
                entry.decimals !== undefined &&
                entry.displayAmount !== undefined;
              const label = entry.symbol ?? entry.asset;
              return `<label>${escapeHtml(label)}<input name="autonomy.${prefix}.${index}" inputmode="${human ? 'decimal' : 'numeric'}" pattern="${human ? '(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?' : '(?:0|[1-9][0-9]*)'}" value="${escapeHtml(human ? entry.displayAmount! : entry.amount)}" required><small>${human ? 'Token amount' : 'Atomic units'}</small></label>`;
            },
          )
          .join('')}</fieldset>`
      : '';
  const cotiLimitFields = [
    ['maximumNativeValuePerAction', 'Maximum COTI sent per action', editor.maximumNativeValuePerAction],
    ['maximumNativeValueCumulative', 'Maximum COTI sent in total', editor.maximumNativeValueCumulative],
    ['maximumNetworkFeePerAction', 'Maximum network cost per action (COTI)', editor.maximumNetworkFeePerAction],
    ['maximumNetworkFeeCumulative', 'Maximum total network cost (COTI)', editor.maximumNetworkFeeCumulative],
  ] as const;
  const countLimitFields = [
    ['maximumActions', 'Maximum actions', editor.maximumActions?.toString()],
    ['maximumMessages', 'Maximum messages', editor.maximumMessages?.toString()],
  ] as const;
  const limits = cotiLimitFields
    .flatMap(([id, label, value]) =>
      value === undefined
        ? []
        : [
            `<label>${escapeHtml(label)}<input name="autonomy.${escapeHtml(id)}" inputmode="decimal" pattern="(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?" value="${escapeHtml(policyAmountDisplay(value, { symbol: 'COTI', decimals: 18 }) ?? value)}" required></label>`,
          ],
    )
    .concat(
      countLimitFields.flatMap(([id, label, value]) =>
        value === undefined
          ? []
          : [
              `<label>${escapeHtml(label)}<input name="autonomy.${escapeHtml(id)}" inputmode="numeric" pattern="(?:0|[1-9][0-9]*)" value="${escapeHtml(value)}" required></label>`,
            ],
      ),
    )
    .join('');
  const priceBands = editor.priceBands.length
    ? `<fieldset class="policy-fields policy-wide"><legend>Allowed price bands</legend>${editor.priceBands
        .map((band, index) => {
          const human =
            band.minimumDisplay !== undefined &&
            band.maximumDisplay !== undefined &&
            band.sellDecimals !== undefined &&
            band.buyDecimals !== undefined;
          const pair = `${band.buySymbol ?? band.buyAsset} per ${band.sellSymbol ?? band.sellAsset}`;
          return human
            ? `<div class="price-band">
              <strong>${escapeHtml(pair)}</strong>
              <label>Minimum price<input name="autonomy.price.${index}.minimum" inputmode="decimal" pattern="(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?|[1-9][0-9]*/[1-9][0-9]*" value="${escapeHtml(band.minimumDisplay!)}" required></label>
              <label>Maximum price<input name="autonomy.price.${index}.maximum" inputmode="decimal" pattern="(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?|[1-9][0-9]*/[1-9][0-9]*" value="${escapeHtml(band.maximumDisplay!)}" required></label>
            </div>`
            : `<div class="price-band">
              <strong>${escapeHtml(pair)} (atomic-unit fallback)</strong>
              <label>Minimum numerator<input name="autonomy.price.${index}.minNumerator" inputmode="numeric" value="${escapeHtml(band.minimumNumerator)}" required></label>
              <label>Minimum denominator<input name="autonomy.price.${index}.minDenominator" inputmode="numeric" value="${escapeHtml(band.minimumDenominator)}" required></label>
              <label>Maximum numerator<input name="autonomy.price.${index}.maxNumerator" inputmode="numeric" value="${escapeHtml(band.maximumNumerator)}" required></label>
              <label>Maximum denominator<input name="autonomy.price.${index}.maxDenominator" inputmode="numeric" value="${escapeHtml(band.maximumDenominator)}" required></label>
            </div>`;
        })
        .join('')}</fieldset>`
    : '';
  const duration = editor.duration
    ? `<small>Current duration: ${escapeHtml(editor.duration)}</small>`
    : '';
  const start = editor.startsAt
    ? `<p class="muted policy-wide">Starts ${escapeHtml(new Date(editor.startsAt).toLocaleString())} (local time). ${duration}</p>`
    : duration;
  return `<section class="policy-editor" aria-labelledby="policy-editor-title">
    <div>
      <h2 id="policy-editor-title">Narrow policy before activation</h2>
      <p class="muted">You may lower budgets, tighten price bands, reduce counts, shorten expiry, or disable the policy-wide consent that lets the agent both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts. Agent Control will reject any broader edit.</p>
    </div>
    <div class="policy-grid">
      ${start}
      <label class="policy-wide">Ends (local time)<input type="datetime-local" name="autonomy.expiresAt" value="${escapeHtml(localDateTimeValue(editor.expiresAt))}" required></label>
      <label class="ack policy-wide"><input type="checkbox" name="autonomy.agentVisiblePrivateAmounts" value="true"${editor.agentVisiblePrivateAmounts ? ' checked' : ''}> Allow this agent to both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.</label>
      ${amountFields('Per-action asset budgets', 'perAction', editor.perActionSpend)}
      ${amountFields('Cumulative asset budgets', 'cumulative', editor.cumulativeSpend)}
      ${limits}
      ${priceBands}
    </div>
  </section>`;
};

const renderConfirmation = (
  prompt: Extract<AgentControlPendingPrompt, { kind: 'confirmation' }>,
  csrfToken: string,
): string => {
  const { request } = prompt;
  const basePresentation = actionPresentation(request.action);
  const isRecurring = request.action === 'create_recurring';
  const isPrivateRecurring =
    isRecurring &&
    request.orderType?.id.includes('private-liquidity');
  const presentation =
    isPrivateRecurring
      ? {
          ...basePresentation,
          title: 'Create recurring private-liquidity order',
        }
      : basePresentation;
  const sourceRows = request.details ?? [];
  const primaryRows = isRecurring
    ? recurringExposureRows(
        sourceRows,
        request.orderType?.assetPrivacy === 'fully-private',
      )
    : sourceRows.filter(({ label }) => {
        const normalized = label.toLowerCase();
        return (
          normalized.includes('you send') ||
          normalized.includes('you receive')
        );
      });
  const otherRows = (request.details ?? []).filter(
    ({ label }) => {
      const normalized = label.toLowerCase();
      if (isTechnicalRow(normalized)) return false;
      if (
        normalized.includes('maximum network cost') ||
        normalized.includes('maximum network fee') ||
        normalized === 'protocol fee'
      ) {
        return false;
      }
      if (
        isRecurring &&
        /(?:you send|you receive|private (?:send|receive|inventory)|sell-side (?:liquidity|inventory)|buy-side (?:liquidity|budget))/u.test(
          normalized,
        )
      ) {
        return false;
      }
      return (
        isRecurring ||
        (!normalized.includes('you send') &&
          !normalized.includes('you receive'))
      );
    },
  );
  if (primaryRows.length === 0) {
    if (isRecurring && request.amounts.length >= 2) {
      primaryRows.push(
        {
          label: isPrivateRecurring
            ? request.orderType?.assetPrivacy === 'fully-private'
              ? 'Sell-side inventory · encrypted on-chain'
              : 'Sell-side inventory'
            : 'Sell-side inventory',
          value: request.amounts[0] ?? '',
        },
        {
          label: isPrivateRecurring
            ? request.orderType?.assetPrivacy === 'fully-private'
              ? 'Buy-side budget · encrypted on-chain'
              : 'Buy-side budget'
            : 'Buy-side budget',
          value: request.amounts[1] ?? '',
        },
      );
    }
  }
  if (primaryRows.length === 0) {
    if (request.assets.length > 0) {
      primaryRows.push({
        label: 'Assets',
        value: request.assets.join(' → '),
      });
    }
    if (request.amounts.length > 0) {
      primaryRows.push({
        label: 'Amounts',
        value: request.amounts.join(' → '),
      });
    }
  }

  const orderType = request.orderTypeLabel
    ? `<div class="order-type">
        <span>Order type</span>
        <strong>${escapeHtml(request.orderTypeLabel)}</strong>
      </div>`
    : '';
  const exposure = primaryRows.length
    ? `<div class="exposure" aria-label="Trade exposure">
        ${renderSummaryRows(primaryRows)}
      </div>`
    : '';
  const details = otherRows.length
    ? `<div class="details-grid">${renderSummaryRows(otherRows)}</div>`
    : '';
  const counterparty = request.counterparty
    ? `<div><span>Counterparty</span><strong class="mono" title="${escapeHtml(request.counterparty)}">${escapeHtml(shortAddress(request.counterparty))}</strong></div>`
    : '';
  const maximumNetworkCost =
    sourceRows.find(({ label }) =>
      /maximum network (?:cost|fee)/iu.test(label),
    )?.value ??
    (request.maximumNetworkFeeCoti
      ? `${request.maximumNetworkFeeCoti} COTI`
      : 'Calculated before signing');
  const step =
    request.authorizationScope === 'complete-logical-action'
      ? 'Complete action'
      : request.stepCount > 1
      ? `Step ${request.stepIndex + 1} of ${request.stepCount}`
      : 'Complete action';
  const technicalSteps = request.technicalDetails?.length
    ? request.technicalDetails
        .map(
          (detail, index) =>
            `<div class="technical-step">
              <strong>Transaction ${index + 1}: ${escapeHtml(detail.kind)}</strong>
              <dl class="technical">
                <div><dt>Step</dt><dd>${escapeHtml(detail.stepId)}</dd></div>
                <div><dt>Contract</dt><dd>${escapeHtml(detail.contract)}</dd></div>
                <div><dt>Selector</dt><dd>${escapeHtml(detail.selector)}</dd></div>
                <div><dt>Calldata digest</dt><dd>${escapeHtml(detail.calldataDigest)}</dd></div>
                <div><dt>Gas limit</dt><dd>${escapeHtml(detail.gasCap)}</dd></div>
                <div><dt>Maximum network fee</dt><dd>${escapeHtml(detail.maximumNetworkFeeWei)} wei</dd></div>
              </dl>
            </div>`,
        )
        .join('')
    : '';
  const technicalRows = sourceRows.filter(({ label }) =>
    isTechnicalRow(label),
  );
  const technicalSummary = technicalRows.length
    ? `<dl class="technical">${technicalRows
        .map(
          ({ label, value }) =>
            `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`,
        )
        .join('')}</dl>`
    : '';
  const acknowledgements = request.acknowledgements?.length
    ? `<fieldset class="acknowledgements">
        <legend>Required acknowledgements</legend>
        ${request.acknowledgements
          .map(
            (acknowledgement, index) =>
              `<label class="ack"><input type="checkbox" name="ack${index}" value="yes" required> ${escapeHtml(acknowledgement)}</label>`,
          )
          .join('')}
      </fieldset>`
    : '';
  const autonomyEditor = renderAutonomyEditor(request);

  return `<section class="approval-card" aria-labelledby="approval-title">
    <div class="eyebrow-row">
      <span class="badge badge-purple">Manual approval</span>
      <span class="badge">${escapeHtml(privacyLabel(request))}</span>
      <span class="step">${escapeHtml(step)}</span>
    </div>
    <h1 id="approval-title">${escapeHtml(presentation.title)}</h1>
    <p class="lead">${escapeHtml(request.summary)}</p>
    ${orderType}
    ${
      isRecurring
        ? '<p class="recurring-note">Recurring means reusable two-sided liquidity. It does not schedule automatic trades.</p>'
        : ''
    }
    ${exposure}
    <div class="stats" aria-label="Action costs and destination">
      <div><span>Protocol fee</span><strong>${escapeHtml(request.fee)}</strong></div>
      <div><span>Maximum network cost</span><strong>${escapeHtml(maximumNetworkCost)}</strong></div>
      ${counterparty}
    </div>
    ${details}
    <div class="result">
      <span>Expected result</span>
      <p>${escapeHtml(request.expectedResult)}</p>
    </div>
    <details>
      <summary>Technical details</summary>
      <dl class="technical">
        <div><dt>Wallet</dt><dd>${escapeHtml(request.wallet)}</dd></div>
        <div><dt>Contract</dt><dd>${escapeHtml(request.contract)}</dd></div>
        ${
          request.counterparty
            ? `<div><dt>Full counterparty</dt><dd>${escapeHtml(request.counterparty)}</dd></div>`
            : ''
        }
        ${
          request.spender
            ? `<div><dt>Allowance spender</dt><dd>${escapeHtml(request.spender)}</dd></div>`
            : ''
        }
        <div><dt>Native value</dt><dd>${escapeHtml(request.nativeValue)}</dd></div>
        <div><dt>Gas limit</dt><dd>${escapeHtml(request.gasCap)}</dd></div>
        <div><dt>Operation hash</dt><dd>${escapeHtml(request.operationHash)}</dd></div>
        <div><dt>Step identifier</dt><dd>${escapeHtml(request.stepId)}</dd></div>
      </dl>
      ${technicalSummary}
      ${technicalSteps}
    </details>
    <form method="post" action="/action">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      <input type="hidden" name="promptId" value="${escapeHtml(prompt.id)}">
      <input type="hidden" name="intent" value="prompt">
      ${autonomyEditor}
      ${acknowledgements}
      <div class="actions">
        <button class="button button-secondary" name="action" value="decline" formnovalidate>Decline</button>
        <button class="button button-primary" name="action" value="confirm">${escapeHtml(request.actionButtonLabel ?? presentation.button)}</button>
      </div>
    </form>
  </section>`;
};

const renderPrivateValues = (
  prompt: Extract<AgentControlPendingPrompt, { kind: 'private-values' }>,
  csrfToken: string,
): string => {
  const fields = prompt.request.fields
    .map((field, index) => {
      const inputType = field.kind === 'access-secret' ? 'password' : 'text';
      const inputMode =
        field.kind === 'decimal-amount' ? ' inputmode="decimal"' : '';
      const autoFocus = index === 0 ? ' autofocus' : '';
      return `<div class="field">
        <label for="${escapeHtml(field.id)}">${escapeHtml(field.title)}</label>
        <p id="${escapeHtml(field.id)}-hint">${escapeHtml(field.description)}</p>
        <input id="${escapeHtml(field.id)}" name="${escapeHtml(field.id)}"
          type="${inputType}"${inputMode}${autoFocus} required
          autocomplete="off" autocapitalize="none" spellcheck="false"
          aria-describedby="${escapeHtml(field.id)}-hint">
      </div>`;
    })
    .join('');

  return `<section class="approval-card" aria-labelledby="private-title">
    <div class="eyebrow-row">
      <span class="badge badge-purple">Private input</span>
      <span class="badge">Local signer only</span>
    </div>
    <h1 id="private-title">Enter private order values</h1>
    <p class="lead">This action uses local signer input. To let the agent choose these trade values, prepare it in agent-provided mode and approve it manually or through an autonomy policy.</p>
    <div class="privacy-note">
      Never enter an Agent Wallet private key or recovery phrase in an order-value form. Wallet setup has its own local section.
    </div>
    <form method="post" action="/action">
      <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
      <input type="hidden" name="promptId" value="${escapeHtml(prompt.id)}">
      <input type="hidden" name="intent" value="prompt">
      ${fields}
      <details>
        <summary>Request details</summary>
        <dl class="technical">
          <div><dt>Agent Wallet</dt><dd>${escapeHtml(prompt.request.wallet)}</dd></div>
          <div><dt>Operation hash</dt><dd>${escapeHtml(prompt.request.operationHash)}</dd></div>
        </dl>
      </details>
      <div class="actions">
        <button class="button button-secondary" name="action" value="decline" formnovalidate>Decline</button>
        <button class="button button-primary" name="action" value="confirm">Continue to review</button>
      </div>
    </form>
  </section>`;
};

const safeTransactionUrl = (value: string | undefined): string | null => {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.toString() : null;
  } catch {
    return null;
  }
};

const redactDiagnostic = (value: string): string => {
  if (/(?:private.?key|mnemonic|recovery.?phrase|aes.?key|passphrase|secret)/iu.test(value)) {
    return '[redacted]';
  }
  return value.replace(/\b0x[0-9a-f]{64}\b/giu, '[redacted]');
};

const renderWalletSetup = (
  summary: AgentControlSummary,
  csrfToken: string,
): string => {
  const setup = summary.walletSetup;
  if (!setup) return '';
  const path = escapeHtml(setup.environmentFilePath);
  const backup = setup.generatedBackup
    ? `<section class="wallet-backup" aria-labelledby="wallet-backup-title">
        <span class="badge badge-purple">Backup required</span>
        <h2 id="wallet-backup-title">Save this Agent Wallet key now</h2>
        <p class="muted">This is the only recovery method. ChainWhisper cannot recover it later.</p>
        <div class="copy-field">
          <label for="generated-wallet-address">Agent Wallet address</label>
          <div><input id="generated-wallet-address" readonly value="${escapeHtml(setup.generatedBackup.address)}"><button type="button" class="button button-secondary" data-copy-target="generated-wallet-address">Copy address</button></div>
        </div>
        <div class="copy-field">
          <label for="generated-wallet-key">Private key</label>
          <div><input id="generated-wallet-key" readonly value="${escapeHtml(setup.generatedBackup.privateKey)}"><button type="button" class="button button-secondary" data-copy-target="generated-wallet-key">Copy private key</button></div>
        </div>
        <form method="post" action="/action">
          <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
          <input type="hidden" name="intent" value="control">
          <button class="button button-primary" name="action" value="clear-wallet-backup">I saved the private key</button>
        </form>
      </section>`
    : '';
  const restart = setup.restartRequired
    ? `<div class="notice" role="status">Agent Wallet saved. Restart the signer connection to load it, then fund the address with COTI for gas and the assets the agent may trade.</div>`
    : '';
  const blocked = setup.replacementBlockedReason
    ? `<div class="notice notice-error" role="alert">${escapeHtml(setup.replacementBlockedReason)}</div>`
    : '';
  const replacing = !setup.required;
  return `<section class="wallet-setup" aria-labelledby="wallet-setup-title">
    <div class="section-heading">
      <div>
        <span class="kicker">${replacing ? 'Local wallet management' : 'One-time local setup'}</span>
        <h2 id="wallet-setup-title">${replacing ? 'Replace Agent Wallet' : 'Set up Agent Wallet'}</h2>
      </div>
      <span class="badge">Keys stay on this device</span>
    </div>
    <p class="lead">${replacing
      ? 'Replacement is available only when no operation is pending and no autonomy policy is active.'
      : 'Use a dedicated, minimally funded wallet for agent activity. Import and generation happen only on this local page.'}</p>
    ${restart}
    ${blocked}
    ${backup}
    <div class="setup-grid">
      <form method="post" action="/action" class="setup-card">
        <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
        <input type="hidden" name="intent" value="control">
        <span class="badge badge-purple">Recommended</span>
        <h3>Use existing wallet</h3>
        <p class="muted">Paste a standard 32-byte EVM private key. It is written directly to the selected local .env file.</p>
        <label for="wallet-private-key">Agent Wallet private key</label>
        <input id="wallet-private-key" name="privateKey" type="password" required
          pattern="(?:0x)?[0-9a-fA-F]{64}" autocomplete="off" autocapitalize="none" spellcheck="false">
        <label for="wallet-env-path">Configured signer .env file</label>
        <input id="wallet-env-path" name="environmentFilePath" value="${path}" required readonly autocomplete="off" spellcheck="false">
        ${replacing ? '<label class="ack"><input type="checkbox" name="confirmReplacement" value="replace-agent-wallet" required> I approve replacing the current Agent Wallet after restart.</label>' : ''}
        <button class="button button-primary" name="action" value="import-wallet">Save existing wallet</button>
      </form>
      <form method="post" action="/action" class="setup-card">
        <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
        <input type="hidden" name="intent" value="control">
        <h3>Create new wallet</h3>
        <p class="muted">The signer generates the key with the operating system cryptographic random source and shows it once for backup.</p>
        <label for="generated-env-path">Configured signer .env file</label>
        <input id="generated-env-path" name="environmentFilePath" value="${path}" required readonly autocomplete="off" spellcheck="false">
        ${replacing ? '<label class="ack"><input type="checkbox" name="confirmReplacement" value="replace-agent-wallet" required> I approve replacing the current Agent Wallet after restart.</label>' : ''}
        <button class="button button-secondary" name="action" value="generate-wallet">Create new Agent Wallet</button>
      </form>
    </div>
    <p class="muted compact">${setup.restartRequired ? 'After restart, fund' : 'Fund'} the displayed address with COTI for network fees and only the tokens you want the agent to use. Privacy onboarding is completed from this page after funding.</p>
  </section>`;
};

const renderControlSummary = (
  summary: AgentControlSummary,
  csrfToken: string,
): string => {
  const autonomy = summary.autonomy ?? { mode: 'manual' as const };
  const modeLabel =
    autonomy.mode === 'full'
      ? 'Full autonomy'
      : autonomy.mode === 'bounded'
        ? 'Bounded autonomy'
        : 'Manual signing';
  const stateLabel = autonomy.state ? humanize(autonomy.state) : 'Ready';
  const privateAmountAuthority =
    autonomy.mode === 'manual'
      ? ''
      : autonomy.agentVisiblePrivateAmounts
        ? '<p class="muted">This policy lets the agent both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.</p>'
        : '<p class="muted">This policy does not let the agent choose private amounts or view policy-scoped private balances, hidden order inventory/progress, or participant receipts.</p>';
  const budgetRows = autonomy.remainingBudgets?.length
    ? renderSummaryRows(autonomy.remainingBudgets)
    : '<p class="muted">No autonomous spending policy is active.</p>';
  const actions = summary.controlActions;
  const operations = summary.recentOperations?.length
    ? summary.recentOperations
        .map((operation) => {
          const url = safeTransactionUrl(operation.transactionUrl);
          const setupActions = actions?.enablePrivateToken
            ? (operation.setupAssets ?? [])
                .map(
                  (asset) => `<form method="post" action="/action">
                    <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
                    <input type="hidden" name="intent" value="control">
                    <input type="hidden" name="token" value="${escapeHtml(asset)}">
                    <button class="button button-primary" name="action" value="enable-private-token">Prepare ${escapeHtml(asset)}</button>
                  </form>`,
                )
                .join('')
            : '';
          const localActions =
            operation.operationId && operation.operationHash
              ? [
                  operation.recoverable
                    ? `<form method="post" action="/action">
                        <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
                        <input type="hidden" name="intent" value="control">
                        <input type="hidden" name="operationId" value="${escapeHtml(operation.operationId)}">
                        <button class="button button-secondary" name="action" value="recover-operation">Reconcile</button>
                      </form>`
                    : '',
                  operation.discardable
                    ? `<form method="post" action="/action">
                        <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
                        <input type="hidden" name="intent" value="control">
                        <input type="hidden" name="operationId" value="${escapeHtml(operation.operationId)}">
                        <input type="hidden" name="operationHash" value="${escapeHtml(operation.operationHash)}">
                        <button class="button button-danger" name="action" value="discard-operation">Discard local data</button>
                      </form>`
                    : '',
                ].join('')
              : '';
          return `<li>
            <span><strong>${escapeHtml(operation.label)}</strong><small>${escapeHtml(humanize(operation.status))}</small></span>
            <div class="operation-actions">
              ${url ? `<a href="${escapeHtml(url)}" target="_blank" rel="noreferrer noopener">View transaction</a>` : ''}
              ${setupActions}
              ${localActions}
            </div>
          </li>`;
        })
        .join('')
    : '<li class="empty">No recent signer operations.</li>';
  const diagnostics = summary.diagnostics?.length
    ? `<dl class="diagnostics">${summary.diagnostics
        .map(
          ({ label, value }) =>
            `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(redactDiagnostic(value))}</dd></div>`,
        )
        .join('')}</dl>`
    : '<p class="muted">No signer warnings.</p>';
  const autonomyControls =
    actions?.pause || actions?.resume || actions?.revoke
      ? `<form method="post" action="/action" class="control-actions">
          <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
          <input type="hidden" name="intent" value="control">
          ${actions.pause ? '<button class="button button-warning" name="action" value="pause-autonomy">Pause autonomy</button>' : ''}
          ${actions.resume ? '<button class="button button-secondary" name="action" value="resume-autonomy">Resume autonomy</button>' : ''}
          ${actions.revoke ? '<button class="button button-danger" name="action" value="revoke-autonomy">Revoke policy</button>' : ''}
        </form>`
      : '<p class="muted compact">Autonomy controls appear here when a policy is active.</p>';
  const privacyControl = actions?.onboardPrivacy
    ? `<form method="post" action="/action" class="privacy-control">
        <input type="hidden" name="csrf" value="${escapeHtml(csrfToken)}">
        <input type="hidden" name="intent" value="control">
        <button class="button button-primary" name="action" value="onboard-privacy">Enable private trading</button>
      </form>`
    : '';

  const walletSetup = renderWalletSetup(summary, csrfToken);
  return `${walletSetup}<section class="control-overview" aria-labelledby="control-title">
    <div class="section-heading">
      <div>
        <span class="kicker">Local signer</span>
        <h1 id="control-title">Agent Control</h1>
      </div>
      <span class="status-dot"><i></i>${escapeHtml(
        summary.signerStatus === 'ready' ? 'Signer ready' : humanize(summary.signerStatus ?? 'setup required'),
      )}</span>
    </div>
    <div class="wallet-card">
      <div>
        <span class="kicker">Agent Wallet</span>
        <strong class="wallet-address" title="${escapeHtml(displayValue(summary.wallet))}">${escapeHtml(shortAddress(summary.wallet))}</strong>
      </div>
      <div><span>Network</span><strong>${escapeHtml(displayValue(summary.network))}</strong></div>
      <div><span>Balance</span><strong>${escapeHtml(displayValue(summary.balance))}</strong></div>
      <div><span>Privacy</span><strong>${escapeHtml(humanize(summary.privacyStatus ?? 'unknown'))}</strong>${privacyControl}</div>
    </div>
    <div class="panel-grid">
      <section class="panel">
        <div class="panel-heading"><span>Agent mode</span><span class="badge">${escapeHtml(stateLabel)}</span></div>
        <h2>${escapeHtml(modeLabel)}</h2>
        ${autonomy.expiresAt ? `<p class="muted">Expires ${escapeHtml(autonomy.expiresAt)}</p>` : ''}
        ${privateAmountAuthority}
        ${autonomyControls}
      </section>
      <section class="panel">
        <div class="panel-heading"><span>Remaining policy budgets</span></div>
        <div class="details-grid">${budgetRows}</div>
      </section>
      <section class="panel panel-wide">
        <div class="panel-heading">
          <span>Signer operations</span>
          <span class="badge">${escapeHtml(String(summary.pendingOperations ?? 0))} pending</span>
        </div>
        <ul class="operation-list">${operations}</ul>
      </section>
      <section class="panel panel-wide">
        <div class="panel-heading"><span>Redacted diagnostics</span></div>
        ${diagnostics}
      </section>
    </div>
  </section>`;
};

const styles = `
:root{color-scheme:dark;--bg:#07060b;--surface:#100d18;--surface-2:#171221;--line:#302642;--line-soft:#211a2e;--text:#f6f1ff;--muted:#a99dbb;--purple:#9f6bff;--purple-2:#7744db;--purple-soft:#25183b;--green:#54dfa5;--amber:#ffca6a;--red:#ff7794;--shadow:0 28px 90px rgba(0,0,0,.48)}
*{box-sizing:border-box}html{background:var(--bg)}body{min-height:100vh;margin:0;background:radial-gradient(circle at 12% 0,rgba(120,68,219,.2),transparent 34rem),radial-gradient(circle at 90% 12%,rgba(61,24,101,.22),transparent 30rem),var(--bg);color:var(--text);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input{font:inherit}a{color:#cbb4ff}a:hover{color:#fff}.shell{width:min(1080px,calc(100% - 32px));margin:0 auto;padding:28px 0 42px}.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}.brand{display:flex;align-items:center;gap:11px;font-size:17px;font-weight:780;letter-spacing:-.02em}.local-label{color:var(--muted);font-size:12px;letter-spacing:.08em;text-transform:uppercase}
.approval-card,.control-overview{border:1px solid var(--line);border-radius:24px;background:linear-gradient(145deg,rgba(23,18,33,.98),rgba(12,10,18,.98));box-shadow:var(--shadow);padding:clamp(22px,5vw,46px)}.approval-card{max-width:840px;margin:2vh auto 88px}.eyebrow-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.badge{display:inline-flex;align-items:center;min-height:26px;padding:3px 9px;border:1px solid var(--line);border-radius:999px;color:#cfc4dd;background:#14101d;font-size:12px;font-weight:650}.badge-purple{border-color:#633fa0;color:#e5d8ff;background:var(--purple-soft)}.step{margin-left:auto;color:var(--muted);font-size:13px}h1{font-size:clamp(28px,5vw,44px);line-height:1.08;letter-spacing:-.045em;margin:20px 0 12px}h2{margin:12px 0 4px;font-size:22px;letter-spacing:-.025em}.lead{max-width:680px;margin:0 0 20px;color:#c8bfd3;font-size:16px}.order-type{margin:16px 0;padding:14px 16px;border:1px solid #4e3575;border-radius:14px;background:linear-gradient(90deg,rgba(70,41,108,.42),rgba(30,19,44,.52))}.order-type span,.result span,.wallet-card span,.stats span,.summary-row span,.panel-heading,.kicker{display:block;color:var(--muted);font-size:12px;font-weight:650;letter-spacing:.045em;text-transform:uppercase}.order-type strong{display:block;margin-top:5px;font-size:17px}.recurring-note{margin:10px 0;color:#d7cae8}.exposure{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));overflow:hidden;margin:14px 0;border:1px solid #4a3963;border-radius:16px;background:#0c0911}.exposure .summary-row{min-height:82px;padding:15px 18px;border-right:1px solid #332641}.exposure .summary-row:last-child{border-right:0}.exposure strong{display:block;margin-top:8px;font-size:20px;line-height:1.25}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1px;overflow:hidden;margin:14px 0;border:1px solid var(--line-soft);border-radius:14px;background:var(--line-soft)}.stats>div{min-height:70px;padding:13px;background:#100d18}.stats strong{display:block;margin-top:5px;overflow-wrap:anywhere}.details-grid{margin:14px 0}.details-grid .summary-row{display:flex;justify-content:space-between;gap:24px;padding:9px 0;border-bottom:1px solid var(--line-soft)}.details-grid .summary-row strong{text-align:right;overflow-wrap:anywhere}.result,.privacy-note{margin:16px 0;padding:14px 16px;border-left:3px solid var(--purple);border-radius:4px 12px 12px 4px;background:#110d19}.result p{margin:4px 0 0}.privacy-note{color:#d7cae8;border-left-color:var(--amber)}details{margin:16px 0;border:1px solid var(--line-soft);border-radius:12px;background:#0d0a12}summary{cursor:pointer;padding:14px 16px;color:#c9bdd7;font-weight:650}.technical{margin:0;padding:0 16px 14px}.technical>div{display:grid;grid-template-columns:150px minmax(0,1fr);gap:14px;padding:8px 0;border-top:1px solid var(--line-soft)}dt{color:var(--muted)}dd{margin:0;overflow-wrap:anywhere;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}.actions{position:fixed;z-index:5;left:50%;bottom:0;transform:translateX(-50%);display:flex;justify-content:flex-end;gap:10px;width:min(840px,calc(100% - 24px));padding:12px 0 max(12px,env(safe-area-inset-bottom));border-top:1px solid var(--line);background:rgba(7,6,11,.96);box-shadow:0 -18px 38px rgba(0,0,0,.35)}.control-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:24px}.button{min-height:46px;padding:10px 17px;border:1px solid transparent;border-radius:11px;font-weight:740;cursor:pointer}.button:disabled{cursor:wait;opacity:.7}.button:focus-visible,input:focus-visible,summary:focus-visible,a:focus-visible{outline:3px solid #c6a7ff;outline-offset:3px}.button-primary{color:#0d0618;background:linear-gradient(135deg,#bb94ff,#8c54ef);box-shadow:0 8px 30px rgba(139,83,239,.25)}.button-primary:hover{filter:brightness(1.08)}.button-secondary{color:var(--text);border-color:#493b5d;background:#1b1624}.button-warning{color:#201400;border-color:#a66d13;background:var(--amber)}.button-danger{color:#23030a;border-color:#a8334c;background:var(--red)}.field{margin:22px 0}.field label{display:block;margin-bottom:5px;font-weight:720;font-size:16px}.field p{margin:0 0 9px;color:var(--muted)}.field input{width:100%;min-height:48px;padding:10px 13px;border:1px solid #4b3b60;border-radius:11px;background:#09070d;color:var(--text)}.notice{max-width:840px;margin:0 auto 16px;padding:12px 15px;border:1px solid #3b6d59;border-radius:12px;background:#10231c;color:#b9f3d9}.notice-error{border-color:#773447;background:#291018;color:#ffc1ce}
.section-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:24px}.section-heading h1,.section-heading h2{margin:4px 0 0}.status-dot{display:flex;align-items:center;gap:8px;color:#d9d0e5;font-size:13px}.status-dot i{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 12px rgba(84,223,165,.65)}.wallet-card{display:grid;grid-template-columns:2fr repeat(3,1fr);gap:1px;overflow:hidden;border:1px solid var(--line);border-radius:16px;background:var(--line)}.wallet-card>div{padding:16px 18px;background:#100d18}.wallet-card strong{display:block;margin-top:6px}.wallet-address{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.panel-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-top:14px}.panel{min-height:190px;padding:20px;border:1px solid var(--line-soft);border-radius:16px;background:rgba(12,10,18,.72)}.panel-wide{grid-column:1/-1}.panel-heading{display:flex;justify-content:space-between;gap:16px;align-items:center}.muted{color:var(--muted)}.compact{margin-top:24px}.operation-list{list-style:none;margin:12px 0 0;padding:0}.operation-list li{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:12px 0;border-top:1px solid var(--line-soft)}.operation-list li span{display:flex;flex-direction:column}.operation-list small{color:var(--muted)}.operation-list .empty{color:var(--muted)}.operation-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}.operation-actions form{margin:0}.operation-actions .button{min-height:36px;padding:6px 10px}.diagnostics{margin:12px 0 0}.diagnostics>div{display:grid;grid-template-columns:minmax(120px,1fr) 2fr;gap:18px;padding:9px 0;border-top:1px solid var(--line-soft)}.diagnostics dd{font-family:inherit;font-size:13px}.footer{max-width:760px;margin:22px auto 0;color:#7e738d;text-align:center;font-size:12px}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.wallet-setup{margin-bottom:14px;border:1px solid #4e3575;border-radius:24px;background:linear-gradient(145deg,rgba(31,21,46,.98),rgba(12,10,18,.98));box-shadow:var(--shadow);padding:clamp(22px,5vw,40px)}.setup-grid{display:grid;grid-template-columns:1.15fr .85fr;gap:14px}.setup-card,.wallet-backup{padding:20px;border:1px solid var(--line);border-radius:16px;background:#0d0a13}.setup-card{display:flex;flex-direction:column;gap:10px}.setup-card h3,.wallet-backup h2{margin:4px 0 0}.setup-card label,.copy-field label{font-weight:700}.setup-card>input,.copy-field input{width:100%;min-height:46px;padding:10px 12px;border:1px solid #4b3b60;border-radius:10px;background:#09070d;color:var(--text)}.setup-card .button{margin-top:auto}.ack{display:flex;align-items:flex-start;gap:8px;color:#d7cae8;font-weight:500!important}.ack input{margin-top:5px}.acknowledgements{display:grid;gap:12px;margin:20px 0;padding:16px 18px;border:1px solid #7251a1;border-radius:12px}.acknowledgements legend{padding:0 8px;color:#e3d5f8;font-weight:750}.wallet-backup{margin:16px 0;border-color:#7354a2}.copy-field{margin-top:14px}.copy-field>div{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;margin-top:6px}.copy-field input{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.copy-field .button{min-height:46px}.policy-editor{margin:22px 0;padding:18px;border:1px solid #5d4381;border-radius:14px;background:#0b0810}.policy-editor h2{margin:0}.policy-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:16px}.policy-grid label{display:flex;flex-direction:column;gap:6px;color:#d8cde5;font-size:13px;font-weight:650}.policy-grid input{min-height:42px;padding:8px 10px;border:1px solid #4b3b60;border-radius:9px;background:#09070d;color:var(--text)}.policy-grid .ack{flex-direction:row}.policy-fields{display:grid;gap:10px;margin:0;padding:12px;border:1px solid var(--line-soft);border-radius:10px}.policy-fields legend{padding:0 6px;color:var(--muted)}.policy-wide{grid-column:1/-1}.price-band{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;padding-top:10px;border-top:1px solid var(--line-soft)}.price-band>strong{grid-column:1/-1}
@media(max-width:760px){.shell{width:min(100% - 20px,1080px);padding-top:16px}.local-label{display:none}.approval-card,.control-overview,.wallet-setup{border-radius:18px;padding:22px}.approval-card{margin-bottom:150px}.step{width:100%;margin:2px 0 0}.exposure,.wallet-card,.panel-grid,.setup-grid,.policy-grid,.price-band{grid-template-columns:1fr}.exposure .summary-row{border-right:0;border-bottom:1px solid #332641}.stats{grid-template-columns:1fr}.wallet-card>div:first-child{grid-column:1}.panel-wide,.policy-wide,.price-band>strong{grid-column:auto}.technical>div{grid-template-columns:1fr;gap:3px}.actions,.control-actions{flex-direction:column-reverse}.button{width:100%}.section-heading{flex-direction:column}.details-grid .summary-row{flex-direction:column;gap:4px}.details-grid .summary-row strong{text-align:left}.copy-field>div{grid-template-columns:1fr}}
@media(prefers-reduced-motion:no-preference){.control-overview{animation:enter .22s ease-out both}@keyframes enter{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}}
`;

export const renderAgentControlPage = (
  model: AgentControlPageModel,
  cspNonce: string,
): string => {
  const main = model.pending
    ? model.pending.kind === 'confirmation'
      ? renderConfirmation(model.pending, model.csrfToken)
      : renderPrivateValues(model.pending, model.csrfToken)
    : renderControlSummary(model.summary, model.csrfToken);
  const notice = model.error
    ? `<div class="notice notice-error" role="alert">${escapeHtml(model.error)}</div>`
    : model.flash
      ? `<div class="notice" role="status">${escapeHtml(model.flash)}</div>`
      : '';
  return `<!doctype html>
<html lang="en" data-state-key="${escapeHtml(agentControlStateKey(model))}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Agent Control · ChainWhisper</title>
  <style nonce="${escapeHtml(cspNonce)}">${styles}</style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand"><span>ChainWhisper</span></div>
      <span class="local-label">Agent Control · This device</span>
    </header>
    ${notice}
    <main>${main}</main>
    <footer class="footer">Served by the local ChainWhisper signer at 127.0.0.1. Signing credentials never enter the agent conversation.</footer>
  </div>
  <script nonce="${escapeHtml(cspNonce)}">
    const poll = async () => {
      try {
        const response = await fetch('/snapshot', {
          cache: 'no-store',
          credentials: 'same-origin',
        });
        if (response.ok) {
          const snapshot = await response.json();
          if (
            snapshot.stateKey &&
            snapshot.stateKey !== document.documentElement.dataset.stateKey
          ) {
            location.reload();
            return;
          }
        }
      } catch {}
      setTimeout(poll, document.hidden ? 2000 : 750);
    };
    setTimeout(poll, 750);
    document.addEventListener('submit', (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) return;
      form.setAttribute('aria-busy', 'true');
      for (const button of form.querySelectorAll('button')) {
        button.disabled = true;
        if (button.value === 'confirm') button.textContent = 'Submitting...';
      }
    });
    document.addEventListener('click', async (event) => {
      const button = event.target instanceof Element
        ? event.target.closest('[data-copy-target]')
        : null;
      if (!(button instanceof HTMLButtonElement)) return;
      const target = document.getElementById(button.dataset.copyTarget || '');
      if (!(target instanceof HTMLInputElement)) return;
      try {
        await navigator.clipboard.writeText(target.value);
        button.textContent = 'Copied';
      } catch {
        target.focus();
        target.select();
        button.textContent = 'Select and copy';
      }
    });
  </script>
</body>
</html>`;
};
