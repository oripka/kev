type ImportPhase =
  | 'idle'
  | 'preparing'
  | 'fetchingCvss'
  | 'fetchingEnisa'
  | 'enriching'
  | 'saving'
  | 'savingEnisa'
  | 'complete'
  | 'error'

export type ImportProgressState = {
  phase: ImportPhase
  completed: number
  total: number
  message: string
  startedAt: string | null
  updatedAt: string | null
  error: string | null
}

const defaultState: ImportProgressState = {
  phase: 'idle',
  completed: 0,
  total: 0,
  message: '',
  startedAt: null,
  updatedAt: null,
  error: null
}

declare global {
  // eslint-disable-next-line no-var
  var __kevImportProgress: ImportProgressState | undefined
}

const getState = (): ImportProgressState => {
  if (!globalThis.__kevImportProgress) {
    globalThis.__kevImportProgress = { ...defaultState }
  }

  return globalThis.__kevImportProgress
}

const commit = (patch: Partial<ImportProgressState>) => {
  const state = getState()
  const timestamp = new Date().toISOString()

  globalThis.__kevImportProgress = {
    ...state,
    ...patch,
    updatedAt: timestamp,
    startedAt: patch.phase && patch.phase !== state.phase && patch.phase !== 'idle'
      ? state.startedAt ?? timestamp
      : state.startedAt,
    // When we explicitly reset to idle we also wipe startedAt.
    ...(patch.phase === 'idle'
      ? { startedAt: null, completed: 0, total: 0, error: null, message: '' }
      : {})
  }
}

export const resetImportProgress = () => {
  globalThis.__kevImportProgress = { ...defaultState }
}

export const startImportProgress = (message: string) => {
  commit({
    phase: 'preparing',
    message,
    completed: 0,
    total: 0,
    error: null
  })
}

export const setImportPhase = (phase: ImportPhase, payload: Partial<ImportProgressState> = {}) => {
  commit({
    ...payload,
    phase
  })
}

export const updateImportProgress = (completed: number, total: number, message?: string) => {
  commit({
    phase: 'fetchingCvss',
    completed,
    total,
    message: message ?? getState().message
  })
}

export const completeImportProgress = (message: string) => {
  commit({
    phase: 'complete',
    completed: getState().total,
    message,
    error: null
  })
}

export const failImportProgress = (message: string) => {
  commit({
    phase: 'error',
    message,
    error: message
  })
}

export const getImportProgress = (): ImportProgressState => {
  return { ...getState() }
}
