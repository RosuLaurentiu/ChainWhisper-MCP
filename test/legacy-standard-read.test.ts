import { describe, expect, it } from 'vitest';

import { LiveChainWhisperDomainGateway } from '../src/domain/liveGateway.js';
import { loadRuntimeManifest } from '../src/shared/runtimeManifest.js';

const MAKER =
  '0x1111111111111111111111111111111111111111' as const;
const RECIPIENT =
  '0x2222222222222222222222222222222222222222' as const;
const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000' as const;
const ZERO_HASH = `0x${'00'.repeat(32)}` as const;

describe('legacy Standard order reads', () => {
  it('returns a recipient-bound deployed Standard order with an explicit compatibility type and no false canonical type', async () => {
    const manifest = await loadRuntimeManifest();
    const standard = manifest.contracts.standardEscrow!.address;
    const wisp = manifest.tokens.find(
      (token) => token.symbol === 'WISP'
    );
    if (!wisp?.address) throw new Error('missing-test-wisp');

    const client = {
      async readContract() {
        return [
          [
            MAKER,
            RECIPIENT,
            0,
            [1, wisp.address, 10_000_000n],
            [0, ZERO_ADDRESS, 2_000_000_000_000_000_000n],
            1_753_632_000n,
            0n
          ],
          [false, ZERO_HASH, 3n, 0n],
          [
            10_000_000n,
            2_000_000_000_000_000_000n,
            0n,
            0n
          ],
          [true, 100n, 0n, 0n, false],
          0,
          0n,
          0n,
          7n
        ];
      }
    };
    const gateway = new LiveChainWhisperDomainGateway({
      manifest,
      client
    });

    const result = await gateway.getOrder({
      escrowContract: standard,
      localId: '7'
    });

    expect(result).toMatchObject({
      access: 'direct',
      recipient: RECIPIENT,
      amountVisibility: 'visible',
      legacyCompatibility: {
        kind: 'standard-recipient-bound',
        displayType:
          'Legacy one-off / fixed recipient / public terms',
        canonicalReplacementType: 'one-off.direct'
      },
      relation: {
        kind: 'counter',
        parentOrder: {
          escrowContract: standard.toLowerCase(),
          localId: '3'
        }
      }
    });
    expect(result).not.toHaveProperty('orderType');
  });
});
