export function shortInstanceId(value: string) {
  return value.length > 8 ? value.slice(0, 8) : value
}

export function instanceLabel(value: string | null, localInstanceId: string | null | undefined) {
  if (!value) return null
  if (localInstanceId && value === localInstanceId) return 'Local instance'
  return shortInstanceId(value)
}

export function lineageLabel(value: string, localInstanceId: string | null | undefined) {
  return localInstanceId && value === localInstanceId ? 'Local' : shortInstanceId(value)
}

export function localObjectId(id: string, originInstanceId?: string | null) {
  if (originInstanceId) {
    const prefix = `${originInstanceId}::`
    if (id.startsWith(prefix)) return id.slice(prefix.length)
  }
  const separator = id.indexOf('::')
  return separator >= 0 ? id.slice(separator + 2) : id
}

export type ProvenanceCarrier = {
  origin_instance_id: string | null
  imported_from_instance_id: string | null
  derived_by_instance_id: string | null
}

export function provenanceBadge(node: ProvenanceCarrier, localInstanceId: string | null | undefined) {
  if (node.origin_instance_id && node.origin_instance_id === localInstanceId && !node.imported_from_instance_id && !node.derived_by_instance_id) {
    return 'Local'
  }

  const parts: string[] = []
  if (node.origin_instance_id) parts.push(`origin ${instanceLabel(node.origin_instance_id, localInstanceId)}`)
  if (node.imported_from_instance_id) parts.push(`via ${instanceLabel(node.imported_from_instance_id, localInstanceId)}`)
  if (node.derived_by_instance_id) parts.push(`derived ${instanceLabel(node.derived_by_instance_id, localInstanceId)}`)
  return parts.length ? parts.join(' · ') : 'Unknown origin'
}
