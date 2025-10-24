import { access, mkdir } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { dirname, join } from 'node:path'

export type GitResult = { stdout: string; stderr: string }

export const runGit = async (
  args: string[],
  options: { cwd?: string } = {}
): Promise<GitResult> => {
  const { cwd = process.cwd() } = options
  return new Promise((resolve, reject) => {
    const child = spawn('git', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] })
    const stdoutChunks: Buffer[] = []
    const stderrChunks: Buffer[] = []

    child.stdout.on('data', chunk => stdoutChunks.push(Buffer.from(chunk)))
    child.stderr.on('data', chunk => stderrChunks.push(Buffer.from(chunk)))

    child.on('error', reject)
    child.on('close', code => {
      const stdout = Buffer.concat(stdoutChunks).toString('utf8').trim()
      const stderr = Buffer.concat(stderrChunks).toString('utf8').trim()
      if (code === 0) {
        resolve({ stdout, stderr })
      } else {
        const error = new Error(`git ${args.join(' ')} failed${stderr ? `: ${stderr}` : ''}`)
        reject(error)
      }
    })
  })
}

export const pathExists = async (target: string): Promise<boolean> => {
  try {
    await access(target)
    return true
  } catch {
    return false
  }
}

export const ensureDir = async (target: string) => {
  const directory = dirname(target)
  await mkdir(directory, { recursive: true })
  if (directory !== target) {
    try {
      await mkdir(target, { recursive: true })
    } catch {
      // directory already exists
    }
  }
}

type SyncSparseRepoOptions = {
  repoUrl: string
  branch?: string
  workingDir: string
  sparsePaths: string[]
  useCachedRepository?: boolean
}

export const syncSparseRepo = async ({
  repoUrl,
  branch = 'main',
  workingDir,
  sparsePaths,
  useCachedRepository = false
}: SyncSparseRepoOptions): Promise<{ commit: string | null; updated: boolean }> => {
  const gitDir = join(workingDir, '.git')
  const repoExists = await pathExists(gitDir)

  await ensureDir(workingDir)

  let updated = false
  let previousCommit: string | null = null

  if (repoExists) {
    previousCommit = (
      await runGit(['rev-parse', 'HEAD'], { cwd: workingDir }).catch(() => ({ stdout: '', stderr: '' }))
    ).stdout
  }

  if (!repoExists) {
    await runGit(
      ['clone', '--depth', '1', '--filter=blob:none', '--sparse', repoUrl, workingDir],
      { cwd: process.cwd() }
    )
    updated = true
  } else if (!useCachedRepository) {
    await runGit(['fetch', '--depth', '1', 'origin', branch], { cwd: workingDir })
    await runGit(['reset', '--hard', `origin/${branch}`], { cwd: workingDir })
    await runGit(['clean', '-fdx'], { cwd: workingDir })
    updated = true
  }

  if (sparsePaths.length) {
    await runGit(['sparse-checkout', 'set', ...sparsePaths], { cwd: workingDir }).catch(() => undefined)
  }

  const commitResult = await runGit(['rev-parse', 'HEAD'], { cwd: workingDir }).catch(() => ({ stdout: '', stderr: '' }))
  const commit = commitResult.stdout || null

  if (!updated && commit && previousCommit && commit !== previousCommit) {
    updated = true
  }

  return { commit, updated }
}
