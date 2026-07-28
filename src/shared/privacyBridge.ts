import type { HexString } from './protocol.js';

export type PrivacyBridgePairId =
  | 'coti'
  | 'weth'
  | 'wbtc'
  | 'usdt'
  | 'usdc-e'
  | 'wada'
  | 'gcoti'
  | 'wisp';

export type PrivacyBridgeDirection =
  | 'public-to-private'
  | 'private-to-public';

export type PrivacyBridgePairV1 = {
  id: PrivacyBridgePairId;
  contractName: string;
  bridgeAddress: HexString;
  bridgeKind: 'native' | 'erc20';
  publicSymbol: string;
  privateSymbol: string;
  publicTokenAddress?: HexString;
  privateTokenAddress: HexString;
  decimals: number;
  provider: 'official-coti' | 'chainwhisper';
};

export const PRIVACY_BRIDGE_PAIRS_V1: readonly PrivacyBridgePairV1[] = [
  {
    id: 'coti',
    contractName: 'privacyBridgeCoti',
    bridgeAddress: '0x44D864973392064304dD88E2BDef39fF1ab11b7b',
    bridgeKind: 'native',
    publicSymbol: 'COTI',
    privateSymbol: 'p.COTI',
    privateTokenAddress: '0xD2F2692B83C3ecDF2EAa0f7c2632BBd46Ae1cC91',
    decimals: 18,
    provider: 'official-coti'
  },
  {
    id: 'weth',
    contractName: 'privacyBridgeWeth',
    bridgeAddress: '0x7286c83300f0C7131b4006f3cf9F8e44BeB45c13',
    bridgeKind: 'erc20',
    publicSymbol: 'WETH',
    privateSymbol: 'p.WETH',
    publicTokenAddress: '0x639aCc80569c5FC83c6FBf2319A6Cc38bBfe26d1',
    privateTokenAddress: '0x4727FE8D8450CEBcB142331FAc034Cd8d311f0E5',
    decimals: 18,
    provider: 'official-coti'
  },
  {
    id: 'wbtc',
    contractName: 'privacyBridgeWbtc',
    bridgeAddress: '0xc3B7EdEe4f1c0A0bA1AcD341e4982371eC869862',
    bridgeKind: 'erc20',
    publicSymbol: 'WBTC',
    privateSymbol: 'p.WBTC',
    publicTokenAddress: '0x8C39B1fD0e6260fdf20652Fc436d25026832bfEA',
    privateTokenAddress: '0x65449561257ba5756631Aa0d34f07f6457a319be',
    decimals: 8,
    provider: 'official-coti'
  },
  {
    id: 'usdt',
    contractName: 'privacyBridgeUsdt',
    bridgeAddress: '0x7685B473DAF1c6DeD815Ca64C6fa18Da2227440D',
    bridgeKind: 'erc20',
    publicSymbol: 'USDT',
    privateSymbol: 'p.USDT',
    publicTokenAddress: '0xfA6f73446b17A97a56e464256DA54AD43c2Cbc3E',
    privateTokenAddress: '0x42107250C3D385ddfABE69ab6de163702040FeB0',
    decimals: 6,
    provider: 'official-coti'
  },
  {
    id: 'usdc-e',
    contractName: 'privacyBridgeUsdcE',
    bridgeAddress: '0x29334fC23ffa2c44AF1b372336C2296591Eadd86',
    bridgeKind: 'erc20',
    publicSymbol: 'USDC.e',
    privateSymbol: 'p.USDC.e',
    publicTokenAddress: '0xf1Feebc4376c68B7003450ae66343Ae59AB37D3C',
    privateTokenAddress: '0x63C9a1D05471fc8d47C83968725Dcfdcb5410392',
    decimals: 6,
    provider: 'official-coti'
  },
  {
    id: 'wada',
    contractName: 'privacyBridgeWada',
    bridgeAddress: '0xFa2126C07F517013c8d237cc465342da89B96f92',
    bridgeKind: 'erc20',
    publicSymbol: 'wADA',
    privateSymbol: 'p.wADA',
    publicTokenAddress: '0xe757Ca19d2c237AA52eBb1d2E8E4368eeA3eb331',
    privateTokenAddress: '0x3a8b49aAC1dAD86aa45a75231FbeC5bEb810e416',
    decimals: 6,
    provider: 'official-coti'
  },
  {
    id: 'gcoti',
    contractName: 'privacyBridgeGcoti',
    bridgeAddress: '0xD4e0d9AB16b48c68044cB6aeA3A089380d6D8cD4',
    bridgeKind: 'erc20',
    publicSymbol: 'gCOTI',
    privateSymbol: 'p.gCOTI',
    publicTokenAddress: '0x7637C7838EC4Ec6b85080F28A678F8E234bB83D1',
    privateTokenAddress: '0x394b3c4328160f000763Ca391D07F902926EDaAc',
    decimals: 18,
    provider: 'official-coti'
  },
  {
    id: 'wisp',
    contractName: 'privacyBridgeWisp',
    bridgeAddress: '0x3bCeA2eD4b31107eF877899416dC97213bdc2809',
    bridgeKind: 'erc20',
    publicSymbol: 'WISP',
    privateSymbol: 'p.WISP',
    publicTokenAddress: '0xb70c55bd0823436F44877DC6A9f46E0C55f2C3A8',
    privateTokenAddress: '0x682e3142e62a7aDe2a0CA5bdC87b205CaDe4B17a',
    decimals: 6,
    provider: 'chainwhisper'
  }
] as const;

export const privacyBridgePair = (
  id: string
): PrivacyBridgePairV1 | null =>
  PRIVACY_BRIDGE_PAIRS_V1.find((pair) => pair.id === id) ?? null;
