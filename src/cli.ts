#!/usr/bin/env node
/**
 * ddna - Command line interface for .ddna signing tools
 *
 * Free Commands (no API key needed):
 *   keygen    - Generate Ed25519 key pair
 *   verify    - Verify a .ddna envelope signature
 *   inspect   - Inspect a .ddna envelope
 *   validate  - Validate EDM artifact against schema
 *   redact    - Redact sensitive fields for stateless mode
 *   check-ttl - Check if artifact has expired (24h TTL)
 *
 * Commercial Commands (API key required):
 *   seal      - Seal an EDM artifact into a .ddna envelope ($0.005/seal)
 */

import { Command } from 'commander';
import chalk from 'chalk';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { seal } from './lib/seal.js';
import { verify } from './lib/verify.js';
import { inspect, inspectJson } from './lib/inspect.js';
import { keygen, keyToHex, hexToKey } from './lib/keygen.js';
import { redact, isExpired } from './lib/stateless.js';
import { validate } from './lib/validate.js';

// Get package version
const __dirname = path.dirname(fileURLToPath(import.meta.url));
let version = '0.1.0';
try {
  const pkgPath = path.resolve(__dirname, '..', 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
  version = pkg.version;
} catch {
  // Use default version
}

const program = new Command();

program
  .name('ddna')
  .description('Command line tools for .ddna signing specification')
  .version(version);

/**
 * Read file and parse as JSON
 */
function readJsonFile(filePath: string): object {
  const absolutePath = path.resolve(filePath);

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  const content = fs.readFileSync(absolutePath, 'utf-8');

  try {
    return JSON.parse(content);
  } catch (error) {
    throw new Error(`Invalid JSON in ${filePath}: ${error instanceof Error ? error.message : error}`);
  }
}

/**
 * Read private key from file
 */
function readPrivateKey(keyPath: string): Uint8Array {
  const absolutePath = path.resolve(keyPath);

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Key file not found: ${keyPath}`);
  }

  const content = fs.readFileSync(absolutePath, 'utf-8').trim();

  // Support hex-encoded keys
  try {
    return hexToKey(content);
  } catch {
    throw new Error(`Invalid key format in ${keyPath}: expected 32-byte hex-encoded private key`);
  }
}

/**
 * Generate output filename
 */
function getOutputPath(inputPath: string, extension: string): string {
  const dir = path.dirname(inputPath);
  const basename = path.basename(inputPath);

  // Remove existing extensions like .edm.json, .json
  let name = basename;
  if (name.endsWith('.edm.json')) {
    name = name.slice(0, -9);
  } else if (name.endsWith('.json')) {
    name = name.slice(0, -5);
  }

  return path.join(dir, `${name}${extension}`);
}

// ============================================================================
// SEAL COMMAND
// ============================================================================

program
  .command('seal')
  .description('Seal an EDM artifact into a .ddna envelope (requires API key)')
  .argument('<input>', 'Path to EDM artifact (.edm.json or .json)')
  .requiredOption('-k, --key <path>', 'Path to private key file (hex-encoded)')
  .requiredOption('-d, --did <url>', 'DID URL for verification method')
  .option('-a, --api-key <key>', 'DeepaData API key (or set DEEPADATA_API_KEY env var)')
  .option('-o, --output <path>', 'Output path (default: <input>.ddna)')
  .option('--jurisdiction <code>', 'Override jurisdiction code (e.g., AU, US)')
  .option('--expires <iso8601>', 'Proof expiration timestamp')
  .action(async (input: string, options) => {
    try {
      // Read input file
      const edmPayload = readJsonFile(input);

      // Read private key
      const privateKey = readPrivateKey(options.key);

      // Resolve API key
      const apiKey = options.apiKey || process.env['DEEPADATA_API_KEY'];
      if (!apiKey) {
        console.error(chalk.red('Error:') + ' Sealing requires a DeepaData API key.');
        console.error('  Get one at: ' + chalk.cyan('https://deepadata.com/api-keys'));
        console.error('  Pricing: ' + chalk.cyan('https://deepadata.com/pricing'));
        console.error('');
        console.error('  Set via:');
        console.error('    --api-key <key>');
        console.error('    DEEPADATA_API_KEY environment variable');
        console.error('');
        console.error('  ' + chalk.dim('verify() and inspect() are always free.'));
        process.exit(1);
      }

      // Seal the envelope
      const envelope = await seal(edmPayload, privateKey, options.did, {
        apiKey,
        header: options.jurisdiction ? { jurisdiction: options.jurisdiction } : undefined,
        expires: options.expires,
      });

      // Determine output path
      const outputPath = options.output || getOutputPath(input, '.ddna');

      // Write output
      fs.writeFileSync(outputPath, JSON.stringify(envelope, null, 2));

      console.log(chalk.green('✓') + ' Sealed envelope written to: ' + chalk.cyan(outputPath));
      console.log('  Signed by: ' + chalk.dim(options.did.slice(0, 40) + '...'));
    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// VERIFY COMMAND
// ============================================================================

program
  .command('verify')
  .description('Verify a .ddna envelope signature')
  .argument('<input>', 'Path to .ddna envelope')
  .option('--skip-timestamp', 'Skip timestamp validation')
  .action(async (input: string, options) => {
    try {
      // Read envelope
      const envelope = readJsonFile(input);

      // Verify
      const result = await verify(envelope, {
        skipTimestampCheck: options.skipTimestamp,
      });

      if (result.valid) {
        console.log(chalk.green('VALID') + ' - Signature verified');
        console.log('  Verification Method: ' + chalk.dim(result.verificationMethod));
        console.log('  Created: ' + chalk.dim(result.created));
      } else {
        console.log(chalk.red('INVALID') + ' - ' + result.reason);
        if (result.verificationMethod) {
          console.log('  Verification Method: ' + chalk.dim(result.verificationMethod));
        }
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// INSPECT COMMAND
// ============================================================================

program
  .command('inspect')
  .description('Inspect a .ddna envelope')
  .argument('<input>', 'Path to .ddna envelope')
  .option('--json', 'Output as JSON')
  .action(async (input: string, options) => {
    try {
      // Read envelope
      const envelope = readJsonFile(input);

      if (options.json) {
        // JSON output
        const result = await inspectJson(envelope);
        console.log(JSON.stringify(result, null, 2));
      } else {
        // Human-readable output
        const output = await inspect(envelope);
        console.log(output);
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// KEYGEN COMMAND
// ============================================================================

program
  .command('keygen')
  .description('Generate Ed25519 key pair in DID format')
  .option('-o, --output <prefix>', 'Output file prefix (creates <prefix>.key and <prefix>.pub)')
  .option('--json', 'Output as JSON to stdout')
  .action((options) => {
    try {
      // Generate key pair
      const keys = keygen();

      if (options.json) {
        // JSON output to stdout
        console.log(
          JSON.stringify(
            {
              did: keys.did,
              privateKey: keyToHex(keys.privateKey),
              publicKey: keyToHex(keys.publicKey),
            },
            null,
            2
          )
        );
      } else if (options.output) {
        // Write to files
        const keyPath = `${options.output}.key`;
        const pubPath = `${options.output}.pub`;

        fs.writeFileSync(keyPath, keyToHex(keys.privateKey));
        fs.writeFileSync(pubPath, keyToHex(keys.publicKey));

        console.log(chalk.green('✓') + ' Key pair generated');
        console.log('  Private key: ' + chalk.cyan(keyPath));
        console.log('  Public key:  ' + chalk.cyan(pubPath));
        console.log('  DID:         ' + chalk.yellow(keys.did));
      } else {
        // Output to stdout
        console.log(chalk.bold('Generated Ed25519 Key Pair'));
        console.log('');
        console.log(chalk.cyan('DID:'));
        console.log('  ' + keys.did);
        console.log('');
        console.log(chalk.cyan('Private Key (hex):'));
        console.log('  ' + keyToHex(keys.privateKey));
        console.log('');
        console.log(chalk.cyan('Public Key (hex):'));
        console.log('  ' + keyToHex(keys.publicKey));
        console.log('');
        console.log(chalk.dim('Use --output <prefix> to save to files'));
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// VALIDATE COMMAND (FREE)
// ============================================================================

program
  .command('validate')
  .description('Validate an EDM artifact against v0.5.1 schema (free)')
  .argument('<input>', 'Path to EDM artifact (.edm.json or .json)')
  .option('--json', 'Output as JSON')
  .action((input: string, options) => {
    try {
      // Read input file
      const artifact = readJsonFile(input);

      // Validate
      const result = validate(artifact);

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        if (result.valid) {
          console.log(chalk.green('VALID') + ' - Schema validation passed');
          console.log('  Schema Version: ' + chalk.dim(result.schemaVersion));
        } else {
          console.log(chalk.red('INVALID') + ' - Schema validation failed');
          console.log('  Schema Version: ' + chalk.dim(result.schemaVersion));
          console.log('');
          console.log('Errors:');
          for (const error of result.errors) {
            console.log('  ' + chalk.yellow(error.path) + ': ' + error.message);
            if (error.expected) {
              console.log('    Expected: ' + chalk.dim(error.expected));
            }
            if (error.actual) {
              console.log('    Actual: ' + chalk.dim(error.actual));
            }
          }
          process.exit(1);
        }
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// REDACT COMMAND (FREE)
// ============================================================================

program
  .command('redact')
  .description('Redact sensitive fields for stateless mode (free)')
  .argument('<input>', 'Path to EDM artifact (.edm.json or .json)')
  .option('-o, --output <path>', 'Output path (default: stdout)')
  .option('--json', 'Output as JSON with statistics')
  .action((input: string, options) => {
    try {
      // Read input file
      const artifact = readJsonFile(input);

      // Redact
      const result = redact(artifact);

      if (options.output) {
        // Write to file
        fs.writeFileSync(options.output, JSON.stringify(result.artifact, null, 2));
        console.log(chalk.green('✓') + ' Redacted artifact written to: ' + chalk.cyan(options.output));
        console.log('  Fields redacted: ' + chalk.yellow(result.fieldsRedacted.toString()));
        if (result.redactedPaths.length > 0) {
          console.log('  Paths: ' + chalk.dim(result.redactedPaths.join(', ')));
        }
      } else if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        // Output redacted artifact to stdout
        console.log(JSON.stringify(result.artifact, null, 2));
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// CHECK-TTL COMMAND (FREE)
// ============================================================================

program
  .command('check-ttl')
  .description('Check if artifact has expired based on 24h TTL (free)')
  .argument('<input>', 'Path to EDM artifact (.edm.json or .json)')
  .option('--ttl <hours>', 'Custom TTL in hours (default: 24)', '24')
  .option('--json', 'Output as JSON')
  .action((input: string, options) => {
    try {
      // Read input file
      const artifact = readJsonFile(input);
      const ttlHours = parseInt(options.ttl, 10);

      // Check TTL
      const result = isExpired(artifact, ttlHours);

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        if (result.expired) {
          console.log(chalk.red('EXPIRED') + ' - Artifact has exceeded TTL');
        } else {
          console.log(chalk.green('VALID') + ' - Artifact is within TTL');
        }
        console.log('');
        console.log('  Created: ' + chalk.dim(result.createdAt || 'unknown'));
        console.log('  Age: ' + chalk.dim(result.ageHours + ' hours'));
        console.log('  TTL: ' + chalk.dim(result.ttlHours + ' hours'));
        if (!result.expired) {
          console.log('  Remaining: ' + chalk.green(result.hoursRemaining + ' hours'));
        } else {
          console.log('  Overdue: ' + chalk.red(Math.abs(result.hoursRemaining) + ' hours'));
        }

        if (result.expired) {
          process.exit(1);
        }
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// PARSE AND EXECUTE
// ============================================================================

program.parse();
