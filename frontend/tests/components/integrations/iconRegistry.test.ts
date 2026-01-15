import { describe, it, expect } from 'vitest'
import {
  INTEGRATION_ICONS,
  getIntegrationIcon
} from '@/components/integrations/iconRegistry'
import BitlyIcon from '@/assets/svg-components/third-party/BitlyIcon'
import SlackIcon from '@/assets/svg-components/third-party/SlackIcon'

describe('Integration Icon Registry', () => {
  it('should export Bitly icon in the registry', () => {
    expect(INTEGRATION_ICONS.bitly).toBe(BitlyIcon)
  })

  it('should export Slack icon in the registry', () => {
    expect(INTEGRATION_ICONS.slack).toBe(SlackIcon)
  })

  it('should resolve existing icon by key', () => {
    const IconComponent = getIntegrationIcon('bitly')
    expect(IconComponent).toBe(BitlyIcon)
  })

  it('should resolve existing icon with case normalization', () => {
    const IconComponent = getIntegrationIcon('BITLY')
    expect(IconComponent).toBe(BitlyIcon)
  })

  it('should resolve existing icon with whitespace trimming', () => {
    const IconComponent = getIntegrationIcon('  slack  ')
    expect(IconComponent).toBe(SlackIcon)
  })

  it('should return undefined for unknown icon key', () => {
    const IconComponent = getIntegrationIcon('unknown')
    expect(IconComponent).toBeUndefined()
  })

  it('should return undefined for null/undefined input', () => {
    expect(getIntegrationIcon(null)).toBeUndefined()
    expect(getIntegrationIcon(undefined)).toBeUndefined()
    expect(getIntegrationIcon('')).toBeUndefined()
  })

  it('should return undefined for non-string input', () => {
    expect(getIntegrationIcon(123)).toBeUndefined()
    expect(getIntegrationIcon({})).toBeUndefined()
  })
})
