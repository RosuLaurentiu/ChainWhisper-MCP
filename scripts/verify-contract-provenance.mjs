import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { Interface, keccak256 } from 'ethers';
import solc from 'solc';

const provenanceUrl = new URL(
  '../runtime/coti-mainnet.contract-provenance.v1.json',
  import.meta.url,
);
const manifestUrl = new URL('../runtime/coti-mainnet.v1.json', import.meta.url);
const provenance = JSON.parse(await readFile(provenanceUrl, 'utf8'));
const manifest = JSON.parse(await readFile(manifestUrl, 'utf8'));
const inputOption = process.argv.indexOf('--standard-input');
const standardInputPath =
  inputOption === -1 ? null : process.argv[inputOption + 1];
assert.ok(
  inputOption === -1 || standardInputPath,
  '--standard-input requires an output path.',
);
const [response, creationResponse] = await Promise.all([
  fetch(provenance.contract.sourceApi, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(30_000),
  }),
  fetch(provenance.contract.creationApi, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(30_000),
  }),
]);
assert.equal(
  response.ok,
  true,
  `COTI Scan source request failed with HTTP ${response.status}.`,
);
const payload = await response.json();
assert.equal(
  creationResponse.ok,
  true,
  `COTI Scan creation request failed with HTTP ${creationResponse.status}.`,
);
const creationPayload = await creationResponse.json();
assert.equal(payload.status, '1');
assert.equal(payload.message, 'OK');
assert.equal(payload.result.length, 1);
const verified = payload.result[0];
assert.equal(creationPayload.status, '1');
assert.equal(creationPayload.message, 'OK');
assert.equal(creationPayload.result.length, 1);
const creation = creationPayload.result[0];
assert.equal(verified.ContractName, provenance.contract.name);
assert.equal(
  verified.Address.toLowerCase(),
  provenance.contract.address.toLowerCase(),
);
assert.equal(
  verified.FileName,
  'contracts/ChainWhisperRecurringOTCEscrowV1.sol',
);
assert.equal(verified.ConstructorArguments, provenance.contract.constructorArguments);
assert.equal(
  verified.CompilerVersion.replace(/^v/u, ''),
  provenance.compiler.version,
);
assert.equal(
  Number(verified.OptimizationRuns),
  provenance.compiler.settings.optimizer.runs,
);
for (const [key, value] of Object.entries(provenance.compiler.settings)) {
  assert.deepEqual(verified.CompilerSettings[key], value);
}
assert.equal(solc.version(), provenance.compiler.longVersion);
assert.equal(
  creation.contractAddress.toLowerCase(),
  provenance.contract.address.toLowerCase(),
);
assert.equal(
  creation.contractCreator.toLowerCase(),
  provenance.deployment.creator.toLowerCase(),
);
assert.equal(creation.txHash, provenance.deployment.transactionHash);
assert.equal(Number(creation.blockNumber), provenance.deployment.blockNumber);
assert.equal(Number(creation.timestamp), provenance.deployment.timestamp);

const sourceEntries = [
  [verified.FileName, verified.SourceCode],
  ...verified.AdditionalSources.map((entry) => [
    entry.Filename,
    entry.SourceCode,
  ]),
];
assert.deepEqual(
  sourceEntries.map(([name]) => name).sort(),
  Object.keys(provenance.sources).sort(),
);
const sources = {};
for (const [name, content] of sourceEntries) {
  const hash = createHash('sha256').update(content).digest('hex');
  assert.equal(
    hash,
    provenance.sources[name].sha256,
    `${name} does not match the reviewed deployment source.`,
  );
  sources[name] = { content };
}

const verifiedAbiHash = createHash('sha256')
  .update(verified.ABI)
  .digest('hex');
assert.equal(verifiedAbiHash, provenance.abi.canonicalJsonSha256);
const verifiedAbi = JSON.parse(verified.ABI);
const compilerInput = {
  language: 'Solidity',
  sources,
  settings: {
    ...provenance.compiler.settings,
    outputSelection: {
      '*': {
        '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'],
      },
    },
  },
};
if (standardInputPath) {
  await writeFile(
    standardInputPath,
    `${JSON.stringify(compilerInput, null, 2)}\n`,
    'utf8',
  );
}
const compilerOutput = JSON.parse(solc.compile(JSON.stringify(compilerInput)));
const errors = (compilerOutput.errors ?? []).filter(
  (entry) => entry.severity === 'error',
);
assert.deepEqual(
  errors,
  [],
  errors.map((entry) => entry.formattedMessage).join('\n'),
);
const compiled =
  compilerOutput.contracts?.[verified.FileName]?.[verified.ContractName];
assert.ok(compiled, 'The verified recurring contract was not compiled.');
assert.deepEqual(compiled.abi, verifiedAbi);
const runtimeBytecode = `0x${compiled.evm.deployedBytecode.object}`;
assert.equal((runtimeBytecode.length - 2) / 2, provenance.runtime.bytes);
assert.equal(keccak256(runtimeBytecode), provenance.runtime.keccak256);
const creationBytecode =
  `0x${compiled.evm.bytecode.object}` +
  provenance.contract.constructorArguments.replace(/^0x/u, '');
assert.equal(creationBytecode, creation.creationBytecode);
assert.equal(
  (creationBytecode.length - 2) / 2,
  provenance.deployment.creationBytecodeBytes,
);
assert.equal(
  keccak256(creationBytecode),
  provenance.deployment.creationBytecodeKeccak256,
);

const contractInterface = new Interface(compiled.abi);
for (const [name, selector] of Object.entries(provenance.selectors)) {
  assert.equal(contractInterface.getFunction(name)?.selector, selector);
}
const runtimeEntry = manifest.contracts.recurringEscrow;
assert.equal(
  runtimeEntry.address.toLowerCase(),
  provenance.contract.address.toLowerCase(),
);
assert.equal(runtimeEntry.bytecodeHash, provenance.runtime.keccak256);
assert.equal(runtimeEntry.bytecodeBytes, provenance.runtime.bytes);
for (const [name, selector] of Object.entries(provenance.selectors)) {
  assert.equal(runtimeEntry.selectors[name], selector);
}

process.stdout.write(
  `${JSON.stringify(
    {
      schemaVersion: provenance.schemaVersion,
      verifiedAt: new Date().toISOString(),
      contract: provenance.contract,
      deployment: provenance.deployment,
      compiler: {
        expected: provenance.compiler,
        actual: solc.version(),
      },
      sources: provenance.sources,
      abi: provenance.abi,
      runtime: provenance.runtime,
      selectors: provenance.selectors,
      runtimeManifestMatches: true,
      reproducible: true,
    },
    null,
    2,
  )}\n`,
);
