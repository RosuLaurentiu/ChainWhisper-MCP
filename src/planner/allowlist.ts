import {
  encodeFunctionData,
  parseAbi,
  toFunctionSelector,
  type Abi,
  type Hex
} from 'viem';

import type { PlanStep } from '../domain/types.js';
import type {
  ChainWhisperRuntimeManifestV1,
  RuntimeContractManifestEntry
} from '../shared/runtimeManifest.js';
import type {
  ActionStepV1,
  CanonicalCallArgumentV1,
  HexString
} from '../shared/protocol.js';
import { PRIVACY_BRIDGE_PAIRS_V1 } from '../shared/privacyBridge.js';

const APPROVE_SIGNATURE = 'approve(address,uint256)';
export const APPROVE_SELECTOR = toFunctionSelector(APPROVE_SIGNATURE).toLowerCase() as HexString;
const PRIVATE_APPROVE_SIGNATURE =
  'approve(address,((uint256,uint256),bytes))';
export const PRIVATE_APPROVE_SELECTOR = toFunctionSelector(
  PRIVATE_APPROVE_SIGNATURE
).toLowerCase() as HexString;

type AllowlistedCall = {
  contractName: string;
  selectorName: string;
  functionSignature: string;
};

const BRIDGE_CALLS: readonly AllowlistedCall[] =
  PRIVACY_BRIDGE_PAIRS_V1.flatMap((pair) => [
    {
      contractName: pair.contractName,
      selectorName: 'deposit',
      functionSignature:
        pair.bridgeKind === 'native'
          ? 'deposit(uint256,uint256)'
          : 'deposit(uint256,uint256,uint256)'
    },
    {
      contractName: pair.contractName,
      selectorName: 'withdraw',
      functionSignature: 'withdraw(uint256,uint256,uint256)'
    }
  ]);

const CALLS: readonly AllowlistedCall[] = [
  {
    contractName: 'standardEscrow',
    selectorName: 'createTradeWithPolicy',
    functionSignature:
      'createTradeWithPolicy((uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,uint256,(bool,uint16,uint256,uint256,bool))'
  },
  {
    contractName: 'standardEscrow',
    selectorName: 'fillTrade',
    functionSignature: 'fillTrade(uint256,uint256,uint256)'
  },
  {
    contractName: 'standardEscrow',
    selectorName: 'acceptCounterTradeAndCloseParent',
    functionSignature: 'acceptCounterTradeAndCloseParent(uint256)'
  },
  {
    contractName: 'standardEscrow',
    selectorName: 'counterTradeAndCloseCounteredTrade',
    functionSignature:
      'counterTradeAndCloseCounteredTrade(uint256,(uint8,address,uint256),(uint8,address,uint256),uint64)'
  },
  {
    contractName: 'standardEscrow',
    selectorName: 'cancelTrade',
    functionSignature: 'cancelTrade(uint256)'
  },
  {
    contractName: 'standardEscrow',
    selectorName: 'declineTrade',
    functionSignature: 'declineTrade(uint256)'
  },
  {
    contractName: 'standardEscrow',
    selectorName: 'extendTradeExpiry',
    functionSignature: 'extendTradeExpiry(uint256,uint64)'
  },
  {
    contractName: 'standardEscrow',
    selectorName: 'refreshTrade',
    functionSignature: 'refreshTrade(uint256)'
  },
  {
    contractName: 'standardEscrow',
    selectorName: 'reclaimExpiredTrade',
    functionSignature: 'reclaimExpiredTrade(uint256)'
  },
  {
    contractName: 'standardEscrow',
    selectorName: 'editTrade',
    functionSignature:
      'editTrade(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32)'
  },
  {
    contractName: 'standardEscrow',
    selectorName: 'editTradeWithPolicy',
    functionSignature:
      'editTradeWithPolicy(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,(bool,uint16,uint256,uint256,bool))'
  },
  {
    contractName: 'privateEscrow',
    selectorName: 'createPrivateOrderWithRecoveryNote',
    functionSignature:
      'createPrivateOrderWithRecoveryNote((uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)'
  },
  {
    contractName: 'privateEscrow',
    selectorName: 'cancelAndReplacePrivateOrderWithRecoveryNote',
    functionSignature:
      'cancelAndReplacePrivateOrderWithRecoveryNote(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)'
  },
  {
    contractName: 'privateEscrow',
    selectorName: 'fillPrivateOrder',
    functionSignature:
      'fillPrivateOrder(uint256,((uint256,uint256),bytes))'
  },
  {
    contractName: 'privateEscrow',
    selectorName: 'fillPrivateOrderWithEncryptedAccess',
    functionSignature:
      'fillPrivateOrderWithEncryptedAccess(uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))'
  },
  {
    contractName: 'privateEscrow',
    selectorName: 'fillHybridPrivateOrder',
    functionSignature: 'fillHybridPrivateOrder(uint256,uint256)'
  },
  {
    contractName: 'privateEscrow',
    selectorName: 'fillHybridPrivateOrderWithEncryptedAccess',
    functionSignature:
      'fillHybridPrivateOrderWithEncryptedAccess(uint256,uint256,((uint256,uint256),bytes))'
  },
  {
    contractName: 'privateEscrow',
    selectorName: 'cancelTrade',
    functionSignature: 'cancelTrade(uint256)'
  },
  {
    contractName: 'privateEscrow',
    selectorName: 'declineTrade',
    functionSignature: 'declineTrade(uint256)'
  },
  {
    contractName: 'privateEscrow',
    selectorName: 'refreshTrade',
    functionSignature: 'refreshTrade(uint256)'
  },
  {
    contractName: 'privateEscrow',
    selectorName: 'reclaimExpiredTrade',
    functionSignature: 'reclaimExpiredTrade(uint256)'
  },
  {
    contractName: 'directEscrow',
    selectorName: 'createDirectTrade',
    functionSignature:
      'createDirectTrade((uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),address,uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)'
  },
  {
    contractName: 'directEscrow',
    selectorName: 'createDirectCounterTrade',
    functionSignature:
      'createDirectCounterTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)'
  },
  {
    contractName: 'directEscrow',
    selectorName: 'createDirectCounterTradeForParent',
    functionSignature:
      'createDirectCounterTradeForParent(address,uint256,address,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)'
  },
  {
    contractName: 'directEscrow',
    selectorName: 'counterTradeAndCloseCounteredTrade',
    functionSignature:
      'counterTradeAndCloseCounteredTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)'
  },
  {
    contractName: 'directEscrow',
    selectorName: 'editDirectTrade',
    functionSignature:
      'editDirectTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),address,uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)'
  },
  {
    contractName: 'directEscrow',
    selectorName: 'acceptDirectTrade',
    functionSignature:
      'acceptDirectTrade(uint256,((uint256,uint256),bytes))'
  },
  {
    contractName: 'directEscrow',
    selectorName: 'acceptDirectTradeWithEncryptedAccess',
    functionSignature:
      'acceptDirectTradeWithEncryptedAccess(uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))'
  },
  {
    contractName: 'directEscrow',
    selectorName: 'acceptCounterTradeAndCloseParent',
    functionSignature:
      'acceptCounterTradeAndCloseParent(uint256,((uint256,uint256),bytes))'
  },
  {
    contractName: 'directEscrow',
    selectorName: 'cancelTrade',
    functionSignature: 'cancelTrade(uint256)'
  },
  {
    contractName: 'directEscrow',
    selectorName: 'declineTrade',
    functionSignature: 'declineTrade(uint256)'
  },
  {
    contractName: 'directEscrow',
    selectorName: 'reclaimExpiredTrade',
    functionSignature: 'reclaimExpiredTrade(uint256)'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'createRecurringOrder',
    functionSignature:
      'createRecurringOrder((uint8,address),(uint8,address),(uint256,uint256),(uint256,uint256),address,bool,bytes32,uint256,uint256)'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'createRecurringOrderWithRecoveryNote',
    functionSignature:
      'createRecurringOrderWithRecoveryNote((uint8,address),(uint8,address),(uint256,uint256),(uint256,uint256),address,bool,bytes32,uint256,uint256,bytes)'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'createPrivateRecurringOrder',
    functionSignature:
      'createPrivateRecurringOrder((uint8,address),(uint8,address),(uint256,uint256),(uint256,uint256),address,bool,bytes32,uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'createPrivateRecurringOrderWithRecoveryNote',
    functionSignature:
      'createPrivateRecurringOrderWithRecoveryNote((uint8,address),(uint8,address),(uint256,uint256),(uint256,uint256),address,bool,bytes32,uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes),bytes)'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'editOrder',
    functionSignature:
      'editOrder(uint256,(uint256,uint256),(uint256,uint256),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'fillBuySideWithSecret',
    functionSignature:
      'fillBuySideWithSecret(uint256,uint256,uint256,bytes32)'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'fillSellSideWithSecret',
    functionSignature:
      'fillSellSideWithSecret(uint256,uint256,uint256,bytes32)'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'fillPrivateBuySideWithSecret',
    functionSignature:
      'fillPrivateBuySideWithSecret(uint256,uint256,((uint256,uint256),bytes),uint256,bytes32)'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'fillPrivateSellSideWithSecret',
    functionSignature:
      'fillPrivateSellSideWithSecret(uint256,uint256,((uint256,uint256),bytes),uint256,bytes32)'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'pauseOrder',
    functionSignature: 'pauseOrder(uint256)'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'resumeOrder',
    functionSignature: 'resumeOrder(uint256)'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'cancelOrder',
    functionSignature: 'cancelOrder(uint256)'
  },
  {
    contractName: 'recurringEscrow',
    selectorName: 'settleInventory',
    functionSignature: 'settleInventory(uint256)'
  },
  ...BRIDGE_CALLS
] as const;

const normalizeAddress = (value: string): string => value.toLowerCase();
const normalizeSelector = (value: string): string => value.toLowerCase();

const assertManifestCall = (
  manifest: ChainWhisperRuntimeManifestV1,
  call: AllowlistedCall
): { contract: RuntimeContractManifestEntry; selector: HexString } => {
  const contract = manifest.contracts[call.contractName];
  const selector = contract?.selectors[call.selectorName];
  const derived = toFunctionSelector(call.functionSignature);
  if (
    !contract ||
    !selector ||
    normalizeSelector(selector) !== normalizeSelector(derived)
  ) {
    throw new Error(
      `runtime-selector-mismatch:${call.contractName}.${call.selectorName}`
    );
  }
  return { contract, selector };
};

export const findAllowlistedCall = (
  manifest: ChainWhisperRuntimeManifestV1,
  contractAddress: string,
  selector: string
): AllowlistedCall | null => {
  const normalizedContract = normalizeAddress(contractAddress);
  const normalizedSelector = normalizeSelector(selector);
  for (const call of CALLS) {
    const { contract, selector: manifestSelector } = assertManifestCall(
      manifest,
      call
    );
    if (
      normalizeAddress(contract.address) === normalizedContract &&
      normalizeSelector(manifestSelector) === normalizedSelector
    ) {
      return call;
    }
  }
  return null;
};

const encodeSignature = (
  functionSignature: string,
  args: readonly unknown[]
): HexString => {
  const functionName = functionSignature.slice(
    0,
    functionSignature.indexOf('(')
  );
  // The signature is selected from the closed CALLS table above. `parseAbi`
  // cannot retain a literal type after that runtime lookup, so the boundary is
  // cast only after the allowlist check.
  const abi = parseAbi([`function ${functionSignature}`] as never) as Abi;
  return encodeFunctionData({
    abi,
    functionName,
    args
  }) as HexString;
};

export const encodeAllowlistedPlanStep = (
  manifest: ChainWhisperRuntimeManifestV1,
  step: PlanStep
): {
  data: HexString;
  callTemplate?: ActionStepV1['callTemplate'];
} => {
  const encoding = step.encoding;
  if (!encoding) {
    throw new Error(`plan-step-encoding-missing:${step.id}`);
  }
  if (step.kind === 'approval') {
    const privateApproval = step.approvalScheme === 'coti-private-exact';
    const expectedSelector = privateApproval
      ? PRIVATE_APPROVE_SELECTOR
      : APPROVE_SELECTOR;
    const signature = privateApproval
      ? PRIVATE_APPROVE_SIGNATURE
      : APPROVE_SIGNATURE;
    if (
      normalizeSelector(encoding.selector) !== expectedSelector ||
      encoding.arguments.length !== 2
    ) {
      throw new Error(`approval-selector-not-allowlisted:${step.id}`);
    }
    return {
      data: encodeSignature(signature, encoding.arguments),
      callTemplate: {
        functionSignature: signature,
        arguments: encoding.arguments as CanonicalCallArgumentV1[]
      }
    };
  }
  const call = findAllowlistedCall(
    manifest,
    step.contract,
    encoding.selector
  );
  if (!call) {
    throw new Error(`protocol-selector-not-allowlisted:${step.id}`);
  }
  const data = encodeSignature(call.functionSignature, encoding.arguments);
  if (
    normalizeSelector(data.slice(0, 10)) !==
    normalizeSelector(encoding.selector)
  ) {
    throw new Error(`encoded-selector-mismatch:${step.id}`);
  }
  return {
    data,
    callTemplate: {
      functionSignature: call.functionSignature,
      arguments: encoding.arguments as CanonicalCallArgumentV1[]
    }
  };
};

export const encodeReadCall = (
  functionSignature: string,
  args: readonly unknown[] = []
): Hex =>
  encodeSignature(functionSignature, args);

export const allowlistedProtocolCalls = (): readonly AllowlistedCall[] => CALLS;
