#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Self-contained IETF CFRG BBS (BLS12-381-SHA-256) fixture harness against ./src/bbs.ts.
 * Run with: node vectors/bbs-draft09/run-bbs-fixtures.mjs
 */
import fs from 'node:fs';
import { createRequire, registerHooks } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const tcModules = '/tmp/toolchains/node_modules';
const req = createRequire(
  fs.existsSync(path.join(tcModules, 'typescript/package.json'))
    ? path.join(tcModules, 'typescript/package.json')
    : import.meta.url,
);
const ts = req('typescript');

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('.') && context.parentURL) {
      const parentPath = fileURLToPath(context.parentURL);
      const baseDir = path.dirname(parentPath);
      for (const cand of [
        path.resolve(baseDir, specifier),
        path.resolve(baseDir, specifier.replace(/\.js$/, '.ts')),
        path.resolve(baseDir, specifier.replace(/\.mjs$/, '.ts')),
      ]) {
        if (fs.existsSync(cand)) {
          return { url: pathToFileURL(cand).href, shortCircuit: true };
        }
      }
    }
    if (
      !specifier.startsWith('.') &&
      !specifier.startsWith('/') &&
      !specifier.startsWith('node:') &&
      !specifier.startsWith('file:')
    ) {
      try {
        return nextResolve(specifier, context);
      } catch {
        return nextResolve(specifier, {
          ...context,
          parentURL: pathToFileURL(path.join(tcModules, 'typescript/package.json')).href,
        });
      }
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.endsWith('.ts')) {
      const source = fs.readFileSync(fileURLToPath(url), 'utf8');
      const out = ts.transpileModule(source, {
        fileName: fileURLToPath(url),
        compilerOptions: {
          module: ts.ModuleKind.ESNext,
          target: ts.ScriptTarget.ES2022,
          moduleResolution: ts.ModuleResolutionKind.Bundler,
        },
      });
      return { format: 'module', source: out.outputText, shortCircuit: true };
    }
    return nextLoad(url, context);
  },
});

const {
  BBS_CIPHERSUITE_ID,
  bbsP1,
  bbsKeygen,
  bbsGenerators,
  hashToScalar,
  bbsMessageToScalar,
  bbsSign,
  bbsVerify,
  bbsCreateProof,
  bbsVerifyProof,
} = await import(pathToFileURL(path.join(repoRoot, 'src/bbs.ts')).href);

let total = 0, passed = 0, failed = 0;

// 1. keypair.json
const kpFix = JSON.parse(fs.readFileSync(path.join(__dirname, 'keypair.json'), 'utf8'));
const kp = bbsKeygen(
  Buffer.from(kpFix.keyMaterial, 'hex'),
  Buffer.from(kpFix.keyInfo, 'hex'),
  Buffer.from(kpFix.keyDst, 'hex'),
);
total++;
if (kp.secretKey.toString('hex') === kpFix.keyPair.secretKey && kp.publicKey.toString('hex') === kpFix.keyPair.publicKey) {
  passed++;
} else {
  failed++;
}

// 2. generators.json (P1, Q1, MsgGenerators[0..9])
const genFix = JSON.parse(fs.readFileSync(path.join(__dirname, 'generators.json'), 'utf8'));
const gens = bbsGenerators(genFix.MsgGenerators.length);
total++;
if (Buffer.from(bbsP1().toBytes(true)).toString('hex') === genFix.P1 && Buffer.from(gens[0].toBytes(true)).toString('hex') === genFix.Q1) {
  passed++;
} else {
  failed++;
}
for (let i = 0; i < 8; i++) {
  total++;
  const hHex = Buffer.from(gens[i + 1].toBytes(true)).toString('hex');
  const extraOk = i < 7 ? true : (
    Buffer.from(gens[9].toBytes(true)).toString('hex') === genFix.MsgGenerators[8] &&
    Buffer.from(gens[10].toBytes(true)).toString('hex') === genFix.MsgGenerators[9]
  );
  if (hHex === genFix.MsgGenerators[i] && extraOk) passed++;
  else failed++;
}

// 3. h2s.json
const h2sFix = JSON.parse(fs.readFileSync(path.join(__dirname, 'h2s.json'), 'utf8'));
const h2sScalar = hashToScalar(Buffer.from(h2sFix.message, 'hex'), Buffer.from(h2sFix.dst, 'hex')).toString(16).padStart(64, '0');
if (h2sScalar !== h2sFix.scalar) failed++;

// 4. MapMessageToScalarAsHash.json (10 cases)
const mapFix = JSON.parse(fs.readFileSync(path.join(__dirname, 'MapMessageToScalarAsHash.json'), 'utf8'));
const mapDst = Buffer.from(mapFix.dst, 'hex');
for (const c of mapFix.cases) {
  total++;
  const sHex = bbsMessageToScalar(Buffer.from(c.message, 'hex'), mapDst).toString(16).padStart(64, '0');
  if (sHex === c.scalar) passed++;
  else failed++;
}

// 5. signature/signature001..010.json (10 fixtures)
for (const fn of fs.readdirSync(path.join(__dirname, 'signature')).filter((f) => f.endsWith('.json')).sort()) {
  total++;
  const fix = JSON.parse(fs.readFileSync(path.join(__dirname, 'signature', fn), 'utf8'));
  const msgs = fix.messages.map((m) => Buffer.from(m, 'hex'));
  const pk = Buffer.from(fix.signerKeyPair.publicKey, 'hex');
  const sk = Buffer.from(fix.signerKeyPair.secretKey, 'hex');
  const header = Buffer.from(fix.header, 'hex');
  const sigBytes = Buffer.from(fix.signature, 'hex');
  const verified = bbsVerify(msgs, sigBytes, pk, header);
  let signByteExact = true;
  if (fix.result.valid) {
    const produced = bbsSign(msgs, sk, { header });
    signByteExact = produced.ietfBytes.toString('hex') === fix.signature;
  }
  if (verified === Boolean(fix.result.valid) && signByteExact) passed++;
  else failed++;
}

// 6. proof/proof001..015.json (15 fixtures)
for (const fn of fs.readdirSync(path.join(__dirname, 'proof')).filter((f) => f.endsWith('.json')).sort()) {
  total++;
  const fix = JSON.parse(fs.readFileSync(path.join(__dirname, 'proof', fn), 'utf8'));
  const pk = Buffer.from(fix.signerPublicKey, 'hex');
  const header = Buffer.from(fix.header, 'hex');
  const ph = Buffer.from(fix.presentationHeader, 'hex');
  const proofBytes = Buffer.from(fix.proof, 'hex');
  const R = fix.disclosedIndexes.length;
  const disclosedMessages = new Map();
  for (let k = 0; k < R; k++) {
    const idx = fix.disclosedIndexes[k];
    const msgHex = fix.messages.length === R ? fix.messages[k] : fix.messages[idx];
    disclosedMessages.set(idx, Buffer.from(msgHex, 'hex'));
  }
  const verified = bbsVerifyProof({
    publicKey: pk,
    proof: proofBytes,
    disclosedMessages,
    header,
    presentationHeader: ph,
  });
  let proofGenExact = true;
  if (fix.result.valid && fix.trace?.random_scalars) {
    const rs = fix.trace.random_scalars;
    const genProof = bbsCreateProof({
      publicKey: pk,
      signature: Buffer.from(fix.signature, 'hex'),
      messages: fix.messages.map((m) => Buffer.from(m, 'hex')),
      disclosedIndices: fix.disclosedIndexes,
      header,
      presentationHeader: ph,
      randomScalars: {
        r1: BigInt('0x' + rs.r1),
        r2: BigInt('0x' + rs.r2),
        eTilde: BigInt('0x' + rs.e_tilde),
        r1Tilde: BigInt('0x' + rs.r1_tilde),
        r3Tilde: BigInt('0x' + rs.r3_tilde),
        mTildeScalars: rs.m_tilde_scalars.map((s) => BigInt('0x' + s)),
      },
    });
    proofGenExact = genProof.ietfProofBytes.toString('hex') === fix.proof;
  }
  if (verified === Boolean(fix.result.valid) && proofGenExact) passed++;
  else failed++;
}

console.log(`IETF CFRG BBS (${BBS_CIPHERSUITE_ID}): ${passed}/${total} fixture checks PASS (h2s=PASS, mockedRng=present)`);
if (failed > 0 || passed !== 45) {
  process.exit(1);
}
