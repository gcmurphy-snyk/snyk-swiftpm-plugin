import { computeDepGraph as swiftDepGraph } from './swiftpm/compute-depgraph';
import { computeDepGraph as carthageDepGraph } from './carthage/deps';
import { DepGraph } from '@snyk/dep-graph';
import { lookpath } from 'lookpath';
import * as Debug from 'debug';
import * as path from 'path';
import { execFileSync } from 'child_process';

interface Options {
  debug?: boolean;
  file?: string;
  args?: string[];
}

const debug = Debug('snyk');

// we assume that swift considers folders as packages instead of manifest files
function pathToPosix(fpath) {
  const parts = fpath.split(path.sep);
  parts.pop();
  if (parts.length === 0) {
    return './';
  }
  return parts.join(path.posix.sep);
}

const gitRef = (targetFile: string): string | undefined => {
  const args = ['log', '-1', '--oneline', '--', targetFile];
  try {
    const ref = execFileSync('git', args, { stdio: 'pipe', encoding: 'utf8' });
    return ref.split(' ').at(0);
  } catch (e) {
    throw new Error(`unable to determine git ref of ${targetFile}: ${e}`);
  }
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function inspect(
  root: string,
  targetFile: string,
  options?: Options,
) {
  debug(`swift-plugin: root = ${root}, ${targetFile}`);
  debug(options);

  const filename = path.basename(targetFile);
  let depGraph: DepGraph;
  if (filename == 'Package.swift') {
    const swiftPath = await lookpath('swift');
    if (!swiftPath) {
      throw new Error(
        'The "swift" command is not available on your system. ' +
          'To scan your dependencies in the CLI, you must ensure you have ' +
          'first installed the relevant package manager.',
      );
    }
    depGraph = await swiftDepGraph(root, targetFile, options?.args);
  } else if (filename == 'Cartfile.resolved') {
    const gitPath = await lookpath('git');
    if (!gitPath) {
      debug('git not detected - using default version for root package');
    }
    depGraph = await carthageDepGraph(
      root,
      targetFile,
      path.dirname(targetFile),
      gitRef(targetFile) || '0.0.0',
    );
  } else {
    throw new Error(
      `${filename} is not supported by Swift Package Manager or Carthage. ` +
        `Please provide with path to Package.swift or Cartfile.resolved files.`,
    );
  }

  if (!depGraph) {
    throw new Error(`Failed to scan ${targetFile}`);
  }
  return {
    plugin: {
      name: 'snyk-swiftpm-plugin',
      runtime: 'unknown',
      targetFile: `${pathToPosix(targetFile)}${filename}`,
    },
    dependencyGraph: depGraph,
  };
}
