import { resolve } from 'node:path';

export function normalizeConfigPath(configFilePath, homeDir) {
  if (configFilePath === '~') {
    return resolve(homeDir);
  }
  if (configFilePath.startsWith('~/') || configFilePath.startsWith('~\\')) {
    return resolve(homeDir, configFilePath.slice(2));
  }
  return resolve(configFilePath);
}

export function configPathsMatch(reportedPath, expectedPath, homeDir) {
  return normalizeConfigPath(reportedPath, homeDir) === normalizeConfigPath(expectedPath, homeDir);
}

export function reportedConfigPath(output) {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .at(-1);
}
