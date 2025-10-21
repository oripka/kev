import type { MarketProgramDefinition } from '../types'
import { appleProgram } from './apple'
import { crowdfenseProgram } from './crowdfense'
import { opzeroProgram } from './opzero'

export const marketPrograms: MarketProgramDefinition[] = [
  crowdfenseProgram,
  opzeroProgram,
  appleProgram
]
