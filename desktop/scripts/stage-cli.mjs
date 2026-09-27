// Build the `cordon` command line and stage it where the installer picks it
// up (src-tauri/bin). Tauri runs this before every `tauri build`, so an
// installer always ships the CLI from the same source as the app.
//
// It goes in a `bin` folder rather than beside the app because `cordon.exe`
// and `Cordon.exe` are the same file on Windows.

import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const desktop = dirname(dirname(fileURLToPath(import.meta.url)));
const root = dirname(desktop);
const exe = process.platform === 'win32' ? 'cordon.exe' : 'cordon';

// Honour a target triple Tauri was asked for, so a cross build stages the
// matching binary. Tauri always sets one; passing the host's own would build
// every dependency a second time into a separate target folder.
const host = spawnSync('rustc', ['-vV'], { encoding: 'utf8' })
  .stdout?.match(/^host: (.+)$/m)?.[1]?.trim();
const requested = process.env.TAURI_ENV_TARGET_TRIPLE;
const target = requested && requested !== host ? requested : undefined;
const args = ['build', '--release', '-p', 'cordon-cli', '--bin', 'cordon'];
if (target) args.push('--target', target);

console.log(`Building the cordon command line (${args.join(' ')})`);
const built = spawnSync('cargo', args, { cwd: root, stdio: 'inherit' });
if (built.status !== 0) {
  console.error('Building the command line failed.');
  process.exit(built.status ?? 1);
}

const from = join(root, 'target', ...(target ? [target] : []), 'release', exe);
const to = join(desktop, 'src-tauri', 'bin', exe);
mkdirSync(dirname(to), { recursive: true });
copyFileSync(from, to);
console.log(`Staged ${to}`);
