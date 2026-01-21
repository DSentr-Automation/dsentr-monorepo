import { API_BASE_URL } from './config'

export type ActionCatalogInput = {
  name: string
  label?: string | null
  type?: string | null
  required?: boolean | null
  provider?: string | null
  connectionScopes?: string[] | null
  options?: Array<{ value: string; label: string }> | string[] | null
}

export type ActionCatalogEntry = {
  action_id: string
  executor?: string | null
  ui?: {
    label?: string | null
    description?: string | null
    category?: string | null
    icon?: string | null
  } | null
  inputs?: ActionCatalogInput[] | null
}

export async function fetchActionCatalog(): Promise<ActionCatalogEntry[]> {
  const res = await fetch(`${API_BASE_URL}/api/actions`, {
    credentials: 'include'
  })

  if (!res.ok) {
    throw new Error(`Failed to load actions (${res.status})`)
  }

  const data = await res.json()
  return Array.isArray(data) ? (data as ActionCatalogEntry[]) : []
}
