import type { ComponentType, SVGProps } from 'react'

// Import all third-party integration icon components
import AsanaIcon from '@/assets/svg-components/third-party/AsanaIcon'
import BitlyIcon from '@/assets/svg-components/third-party/BitlyIcon'
import GoogleIcon from '@/assets/svg-components/third-party/GoogleIcon'
import MicrosoftIcon from '@/assets/svg-components/third-party/MicrosoftIcon'
import NotionIcon from '@/assets/svg-components/third-party/NotionIcon'
import SlackIcon from '@/assets/svg-components/third-party/SlackIcon'

/**
 * Central registry for integration icons.
 * Maps integration icon keys from manifests to their React SVG components.
 * The icon key from manifest ui.icon is used as the lookup key.
 */
export const INTEGRATION_ICONS: Record<
  string,
  ComponentType<SVGProps<SVGSVGElement>>
> = {
  bitly: BitlyIcon,
  slack: SlackIcon,
  google: GoogleIcon,
  microsoft: MicrosoftIcon,
  asana: AsanaIcon,
  notion: NotionIcon
}

/**
 * Helper function to resolve an integration icon component by key.
 * Returns undefined if the icon is not found, allowing for graceful fallback.
 */
export function getIntegrationIcon(
  iconKey?: string | null
): ComponentType<SVGProps<SVGSVGElement>> | undefined {
  if (!iconKey || typeof iconKey !== 'string') {
    return undefined
  }

  const normalizedKey = iconKey.trim().toLowerCase()
  return INTEGRATION_ICONS[normalizedKey]
}
