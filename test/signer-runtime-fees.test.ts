import { describe, expect, it, vi } from 'vitest';
import {
  encodeAbiParameters,
  toFunctionSelector,
  type Hex,
} from 'viem';

import { ContractRuntimeFeeReader } from '../src/signer/runtime.js';
import type { JsonRpcReader } from '../src/shared/index.js';
import type { Address } from '../src/signer/types.js';

const amountSelector = toFunctionSelector('feeAmount()');
const recipientSelector = toFunctionSelector('feeRecipient()');
const editSelector = toFunctionSelector('chargeFeeOnEdit()');
const recipient = '0x1111111111111111111111111111111111111111';

const resultFor = (selector: Hex): Hex => {
  if (selector === amountSelector) {
    return encodeAbiParameters([{ type: 'uint256' }], [3n]);
  }
  if (selector === recipientSelector) {
    return encodeAbiParameters([{ type: 'address' }], [recipient]);
  }
  if (selector === editSelector) {
    return encodeAbiParameters([{ type: 'bool' }], [true]);
  }
  throw new Error(`unexpected selector ${selector}`);
};

describe('ContractRuntimeFeeReader', () => {
  it('retries transient reads, caps concurrency at four, and preserves action order', async () => {
    vi.useFakeTimers();
    let active = 0;
    let maximumActive = 0;
    let transientFailures = 2;
    const rpc: JsonRpcReader = {
      async request<T>(_method: string, params: unknown[]): Promise<T> {
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await Promise.resolve();
        active -= 1;
        if (transientFailures > 0) {
          transientFailures -= 1;
          throw new Error('rpc-transport-failed');
        }
        const call = params[0] as { data: Hex };
        return resultFor(call.data) as T;
      },
    };
    const actions = Object.fromEntries(
      ['standard', 'private', 'direct', 'recurring'].map((action, index) => [
        action,
        `0x${String(index + 1).padStart(40, '0')}` as Address,
      ]),
    );
    const reader = new ContractRuntimeFeeReader({
      rpc,
      actionContracts: actions,
      editFeeModes: {
        [actions.standard!.toLowerCase()]: 'contract-flag',
      },
    });

    const pending = reader.readFeeState();
    await vi.runAllTimersAsync();
    const state = await pending;

    expect(maximumActive).toBeLessThanOrEqual(4);
    expect(Object.keys(state.fees)).toEqual(Object.keys(actions));
    expect(state.fees).toEqual({
      standard: '3',
      private: '3',
      direct: '3',
      recurring: '3',
    });
    expect(state.editFees?.standard).toBe('3');
    vi.useRealTimers();
  });

  it('exhausts four attempts for a permanent RPC failure', async () => {
    vi.useFakeTimers();
    let attempts = 0;
    const rpc: JsonRpcReader = {
      async request<T>(): Promise<T> {
        attempts += 1;
        throw new Error('rpc-transport-failed');
      },
    };
    const reader = new ContractRuntimeFeeReader({
      rpc,
      actionContracts: {
        standard: '0x0000000000000000000000000000000000000001',
      },
    });

    const pending = reader.readFeeState();
    const rejection = expect(pending).rejects.toThrow(
      'rpc-transport-failed',
    );
    await vi.runAllTimersAsync();
    await rejection;

    expect(attempts).toBe(8);
    vi.useRealTimers();
  });
});
