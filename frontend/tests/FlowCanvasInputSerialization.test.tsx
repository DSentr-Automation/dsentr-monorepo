import { describe, expect, it } from 'vitest'

import {
  formatManifestInputValue,
  parseManifestInputValue
} from '@/layouts/DashboardLayouts/FlowCanvas.helpers'

describe('manifest input serialization', () => {
  it('round-trips numbers', () => {
    const formatted = formatManifestInputValue('number', 42)
    expect(formatted).toBe('42')

    const parsed = parseManifestInputValue('number', formatted as string)
    expect(parsed.error).toBeUndefined()
    expect(parsed.value).toBe(42)
  })

  it('round-trips booleans', () => {
    const formatted = formatManifestInputValue('boolean', true)
    expect(formatted).toBe(true)

    const parsed = parseManifestInputValue('boolean', formatted as boolean)
    expect(parsed.error).toBeUndefined()
    expect(parsed.value).toBe(true)
  })

  it('round-trips string arrays', () => {
    const formatted = formatManifestInputValue('string[]', ['alpha', 'beta'])
    expect(formatted).toBe('alpha, beta')

    const parsed = parseManifestInputValue('string[]', formatted as string)
    expect(parsed.error).toBeUndefined()
    expect(parsed.value).toEqual(['alpha', 'beta'])
  })

  it('round-trips objects', () => {
    const payload = { enabled: true, retries: 3 }
    const formatted = formatManifestInputValue('object', payload)
    expect(typeof formatted).toBe('string')

    const parsed = parseManifestInputValue('object', formatted as string)
    expect(parsed.error).toBeUndefined()
    expect(parsed.value).toEqual(payload)
  })
})
