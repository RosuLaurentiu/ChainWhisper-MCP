import {
  decodeEventLog,
  parseAbiItem,
  type AbiEvent,
} from 'viem';

import type { SignedActionEnvelopeV1 } from '../shared/index.js';
import type {
  Address,
  HexString,
  OperationSemanticResultV2,
  TransactionReceipt,
} from './types.js';

const CHAINWHISPER_APP_ORIGIN = 'https://chainwhisper.chat';
const MAX_APP_LINK_ORDER_ID = BigInt(Number.MAX_SAFE_INTEGER);

// These exact deployed event ABIs are also mirrored by the ChainWhisper app
// in src/lib/appShared/contracts.ts. The signer only accepts the event selected
// by the envelope's canonical route and exact attested protocol target.
const TRADE_OPENED_EVENT = parseAbiItem(
  'event TradeOpened(uint256 indexed tradeId, address indexed maker, address indexed taker, bool isPublic, bytes32 accessHash, uint256 parentTradeId, uint64 createdAt, uint64 expiresAt, uint256 feePaid)',
);
const PRIVATE_ORDER_OPENED_EVENT = parseAbiItem(
  'event PrivateOrderOpened(uint256 indexed tradeId, address indexed maker, address indexed taker, uint8 mode, bool isPublic, bool hasAccessHash, uint64 createdAt, uint64 expiresAt, bytes32 termsHash, uint256 feePaid)',
);
const DIRECT_TRADE_OPENED_EVENT = parseAbiItem(
  'event DirectTradeOpened(uint256 indexed tradeId, address indexed maker, address indexed taker, bool hasAccessHash, uint256 parentTradeId, uint64 createdAt, uint64 expiresAt, bytes32 termsHash, uint256 feePaid)',
);
const RECURRING_ORDER_OPENED_EVENT = parseAbiItem(
  'event RecurringOrderOpened(uint256 indexed orderId, address indexed maker, address indexed taker, uint8 mode, bool isPublic, bool hasAccessHash, uint64 createdAt, uint256 feePaid)',
);

type CreateRoute = {
  contractKey:
    | 'standardEscrow'
    | 'privateEscrow'
    | 'directEscrow'
    | 'recurringEscrow';
  event: AbiEvent;
  idField: 'tradeId' | 'orderId';
  linkKind: 'standard' | 'private' | 'direct' | 'recurring';
};

const CREATE_ROUTES: Readonly<
  Record<
    NonNullable<
      SignedActionEnvelopeV1['intent']['orderType']
    >['route'],
    CreateRoute
  >
> = {
  'standard-escrow': {
    contractKey: 'standardEscrow',
    event: TRADE_OPENED_EVENT,
    idField: 'tradeId',
    linkKind: 'standard',
  },
  'private-liquidity-escrow': {
    contractKey: 'privateEscrow',
    event: PRIVATE_ORDER_OPENED_EVENT,
    idField: 'tradeId',
    linkKind: 'private',
  },
  'direct-escrow': {
    contractKey: 'directEscrow',
    event: DIRECT_TRADE_OPENED_EVENT,
    idField: 'tradeId',
    linkKind: 'direct',
  },
  'recurring-escrow': {
    contractKey: 'recurringEscrow',
    event: RECURRING_ORDER_OPENED_EVENT,
    idField: 'orderId',
    linkKind: 'recurring',
  },
};

const sameAddress = (left: string, right: string): boolean =>
  left.toLowerCase() === right.toLowerCase();

const encodeAppTradeLink = (orderId: bigint): string | null => {
  if (orderId <= 0n || orderId > MAX_APP_LINK_ORDER_ID) return null;
  let byteLength = 1;
  while (orderId >= 1n << BigInt(byteLength * 8)) byteLength += 1;
  const bytes = new Uint8Array(2 + byteLength);
  bytes[0] = 0x54 | 2;
  bytes[1] = (byteLength - 1) << 1;
  let remaining = orderId;
  for (let index = bytes.length - 1; index >= 2; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return Buffer.from(bytes).toString('base64url');
};

const shareableAppLink = (
  orderId: bigint,
  kind: CreateRoute['linkKind'],
): string | null => {
  if (kind === 'recurring') {
    return orderId > 0n && orderId <= BigInt(Number.MAX_SAFE_INTEGER)
      ? `${CHAINWHISPER_APP_ORIGIN}/otc/order/recurring/${orderId}`
      : null;
  }
  const code = encodeAppTradeLink(orderId);
  if (!code) return null;
  const search =
    kind === 'private'
      ? '?escrow=private'
      : kind === 'direct'
        ? '?escrow=direct'
        : '';
  return `${CHAINWHISPER_APP_ORIGIN}/otc/order/link/${code}${search}`;
};

const decodedIdentity = (
  route: CreateRoute,
  receipt: TransactionReceipt,
  target: Address,
  maker: Address,
): { orderId: bigint; appLink: string } | null => {
  if (receipt.status !== 'success' || !receipt.logs) return null;
  const matches: bigint[] = [];
  for (const log of receipt.logs) {
    if (!sameAddress(log.address, target) || log.topics.length === 0) {
      continue;
    }
    try {
      const decoded = decodeEventLog({
        abi: [route.event],
        data: log.data,
        topics: log.topics as [HexString, ...HexString[]],
        strict: true,
      });
      const args = decoded.args as unknown as Record<string, unknown>;
      const orderId = args[route.idField];
      if (
        typeof orderId === 'bigint' &&
        orderId > 0n &&
        typeof args.maker === 'string' &&
        sameAddress(args.maker, maker)
      ) {
        matches.push(orderId);
      }
    } catch {
      // An unrelated or malformed log from the expected contract is not an
      // order identity. Only one exact deployed create event is accepted.
    }
  }
  if (matches.length !== 1) return null;
  const orderId = matches[0]!;
  const appLink = shareableAppLink(orderId, route.linkKind);
  return appLink ? { orderId, appLink } : null;
};

export const decodeCreatedOrderResult = (
  envelope: SignedActionEnvelopeV1,
  receipt: TransactionReceipt,
): OperationSemanticResultV2 | null => {
  const classification = envelope.intent.orderType;
  if (
    !classification ||
    classification.relation !== 'primary' ||
    (
      envelope.intent.action !== 'create_trade' &&
      envelope.intent.action !== 'create_recurring'
    ) ||
    (
      envelope.intent.action === 'create_trade' &&
      classification.cadence !== 'one-off'
    ) ||
    (
      envelope.intent.action === 'create_recurring' &&
      classification.cadence !== 'recurring'
    )
  ) {
    return null;
  }
  const route = CREATE_ROUTES[classification.route];
  const expectedContract =
    envelope.registrySnapshot.contracts[route.contractKey]?.address;
  const protocolTargets = envelope.steps
    .filter(({ kind }) => kind === 'protocol')
    .map(({ to }) => to);
  if (
    !expectedContract ||
    protocolTargets.length !== 1 ||
    !sameAddress(protocolTargets[0]!, expectedContract)
  ) {
    return null;
  }
  const identity = decodedIdentity(
    route,
    receipt,
    expectedContract,
    envelope.wallet,
  );
  if (!identity) return null;
  const localId = identity.orderId.toString();
  return {
    action: envelope.intent.action,
    status: 'completed',
    canonicalType: classification,
    order: {
      handle: `cw_${expectedContract.slice(2).toLowerCase()}_${localId}`,
      status: 'open',
      shareableAppLink: identity.appLink,
    },
  };
};
