#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Self-contained NIST FIPS 204 ACVP v1.1.0.41 ML-DSA-65 conformance harness (180 vectors: 120 sigGen + 60 sigVer).
 * Run with: node vectors/acvp-mldsa65/run-acvp.mjs
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

const { mlDsaSign, mlDsaVerify } = await import(pathToFileURL(path.join(repoRoot, 'src/mldsa.ts')).href);
const { COSE_ALG } = await import(pathToFileURL(path.join(repoRoot, 'src/core/keys.ts')).href);

const sigVer = JSON.parse(fs.readFileSync(path.join(__dirname, 'sigVer-internalProjection.json'), 'utf8'));
const sigGen = JSON.parse(fs.readFileSync(path.join(__dirname, 'sigGen-internalProjection.json'), 'utf8'));

let verTotal = 0, verPass = 0, verFail = 0;
for (const g of sigVer.testGroups.filter((x) => x.parameterSet === 'ML-DSA-65')) {
  for (const t of g.tests) {
    verTotal++;
    const pk = Buffer.from(t.pk, 'hex');
    const sig = Buffer.from(t.signature, 'hex');
    const msg = t.message ? Buffer.from(t.message, 'hex') : Buffer.from(t.mu, 'hex');
    const ctx = t.context ? Buffer.from(t.context, 'hex') : undefined;
    const actual = mlDsaVerify(COSE_ALG.MLDSA65, pk, msg, sig, {
      ...(ctx ? { context: ctx } : {}),
      ...(g.preHash === 'preHash' ? { preHash: t.hashAlg } : {}),
      ...(g.signatureInterface === 'internal' ? { internal: true, externalMu: Boolean(g.externalMu) } : {}),
    });
    if (actual === t.testPassed) verPass++;
    else verFail++;
  }
}

let genTotal = 0, genPass = 0, genFail = 0;
for (const g of sigGen.testGroups.filter((x) => x.parameterSet === 'ML-DSA-65')) {
  for (const t of g.tests) {
    genTotal++;
    const sk = Buffer.from(t.sk, 'hex');
    const expectedSig = Buffer.from(t.signature, 'hex');
    const msg = t.message ? Buffer.from(t.message, 'hex') : Buffer.from(t.mu, 'hex');
    const ctx = t.context ? Buffer.from(t.context, 'hex') : undefined;
    const extraEntropy = g.deterministic ? false : (t.rnd ? Buffer.from(t.rnd, 'hex') : false);
    const actualSig = mlDsaSign(COSE_ALG.MLDSA65, sk, msg, {
      deterministic: Boolean(g.deterministic),
      extraEntropy,
      ...(ctx ? { context: ctx } : {}),
      ...(g.preHash === 'preHash' ? { preHash: t.hashAlg } : {}),
      ...(g.signatureInterface === 'internal' ? { internal: true, externalMu: Boolean(g.externalMu) } : {}),
    });
    if (actualSig.equals(expectedSig)) genPass++;
    else genFail++;
  }
}

console.log(`NIST ACVP v1.1.0.41 ML-DSA-65: sigGen ${genPass}/${genTotal} PASS, sigVer ${verPass}/${verTotal} PASS (total ${genPass + verPass}/${genTotal + verTotal})`);
if (verFail > 0 || genFail > 0 || genPass + verPass !== 180) {
  process.exit(1);
}
