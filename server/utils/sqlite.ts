const SQLITE_BUSY_PATTERN = /(database is locked|SQLITE_BUSY|SQLITE_BUSY_SNAPSHOT)/i

const createSleepBuffer = () => {
  try {
    return new Int32Array(new SharedArrayBuffer(4))
  } catch {
    return null
  }
}

const sleepHandle = createSleepBuffer()

const sleepSync = (milliseconds: number) => {
  if (!sleepHandle || milliseconds <= 0) {
    return
  }
  Atomics.wait(sleepHandle, 0, 0, milliseconds)
}

const isBusyError = (error: unknown): boolean => {
  if (!(error instanceof Error)) {
    return false
  }
  if ('code' in error) {
    const code = String((error as { code?: unknown }).code ?? '')
    if (SQLITE_BUSY_PATTERN.test(code)) {
      return true
    }
  }
  return SQLITE_BUSY_PATTERN.test(error.message)
}

type RetryOptions = {
  attempts?: number
  baseDelayMs?: number
}

export const runWithSqliteRetry = <T>(operation: () => T, options: RetryOptions = {}): T => {
  const attempts = Math.max(1, options.attempts ?? 7)
  const baseDelayMs = Math.max(1, options.baseDelayMs ?? 75)

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return operation()
    } catch (error) {
      const finalAttempt = attempt === attempts - 1
      if (!isBusyError(error) || finalAttempt) {
        throw error
      }
      const delay = baseDelayMs * Math.pow(2, attempt)
      sleepSync(delay)
    }
  }

  throw new Error('runWithSqliteRetry exhausted retries without returning')
}
