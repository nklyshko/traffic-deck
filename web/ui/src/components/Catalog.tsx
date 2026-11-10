import { Trash2 } from 'lucide-react'
import { rem } from '../lib/scale'
import { useState } from 'react'
import * as api from '../lib/api'
import { FAVORITE_TAG, loadCatalog, useCatalog } from '../lib/catalog'
import type { Group } from '../lib/types'
import { MARKS } from './Details'
import { Banner, Button, IconButton, inputClass, Modal, SectionLabel, selectClass } from './ui'

function Confirm({ name, onCancel, onDelete }: { name: string; onCancel: () => void; onDelete: () => void }) {
  return (
    <span className="inline-flex items-center gap-1.5 shrink-0">
      <span className="text-11 text-red-fg">Delete {name}?</span>
      <Button size="xs" onClick={onCancel}>Cancel</Button>
      <Button size="xs" variant="destructive" onClick={onDelete}>Delete</Button>
    </span>
  )
}

function Swatch({ color }: { color?: string }) {
  return <span aria-hidden className={`mark-${color} w-2.5 h-2.5 rounded-full shrink-0`} style={{ background: 'var(--t, var(--dim))' }} />
}

function GroupRow({ group, parents, confirming, onConfirm, onCancel, onSave, onDelete }: {
  group: Group; parents: Group[]; confirming: boolean; onConfirm: () => void; onCancel: () => void; onSave: (g: Group) => void; onDelete: () => void
}) {
  const [name, setName] = useState(group.name ?? '')
  const commit = () => {
    const next = name.trim()
    if (next && next !== group.name) onSave({ ...group, name: next })
    else setName(group.name ?? '')
  }
  return (
    <div className="flex items-center gap-2">
      <Swatch color={group.color} />
      <input aria-label={`Group name ${group.name}`} className={inputClass} value={name} onChange={(e) => setName(e.target.value)} onBlur={commit}
        onKeyDown={(e) => { if (e.key === 'Enter') e.currentTarget.blur() }} />
      <select aria-label="Colour" className={`${selectClass} w-28! shrink-0`} value={group.color ?? ''} onChange={(e) => onSave({ ...group, color: e.target.value })}>
        <option value="">none</option>
        {MARKS.map((m) => <option key={m} value={m}>{m}</option>)}
      </select>
      <select aria-label="Parent group" className={`${selectClass} w-36! shrink-0`} value={group.parentId ?? ''} onChange={(e) => onSave({ ...group, parentId: e.target.value })}>
        <option value="">top level</option>
        {parents.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
      </select>
      {confirming ? <Confirm name={group.name ?? ''} onCancel={onCancel} onDelete={onDelete} />
        : <IconButton label={`Delete ${group.name}`} size={28} className="text-red-fg!" onClick={onConfirm}><Trash2 size={rem(13)} /></IconButton>}
    </div>
  )
}

export function CatalogModal({ onClose }: { onClose: () => void }) {
  const { tags, groups } = useCatalog()
  const [error, setError] = useState('')
  const [confirming, setConfirming] = useState('')
  const [newGroup, setNewGroup] = useState('')
  const run = async (op: () => Promise<unknown>) => {
    try {
      await op()
      setError('')
      setConfirming('')
      await loadCatalog(true)
    } catch (e) {
      setError((e as Error).message)
    }
  }
  const allGroups = [...groups.values()]
  const childrenOf = (id: string): string[] => allGroups.filter((g) => g.parentId === id).flatMap((g) => [g.id, ...childrenOf(g.id)])
  return (
    <Modal title="Manage tags & groups" width={640} onClose={onClose} footer={<Button onClick={onClose}>Done</Button>}>
      {error && <Banner onDismiss={() => setError('')}>{error}</Banner>}
      <div className="space-y-2">
        <SectionLabel count={tags.size}>Tags</SectionLabel>
        {[...tags.values()].map((t) => {
          const favorite = t.isFavorite || t.id === FAVORITE_TAG
          return (
            <div key={t.id} className="flex items-center gap-2 h-7">
              <Swatch color={t.color} />
              <span className="flex-1 min-w-0 truncate text-12 text-ink">{t.name}</span>
              {favorite ? <span className="text-11 text-faint">built in</span>
                : confirming === t.id ? <Confirm name={t.name ?? ''} onCancel={() => setConfirming('')} onDelete={() => void run(() => api.deleteTag(t.id))} />
                  : <IconButton label={`Delete ${t.name}`} size={28} className="text-red-fg!" onClick={() => setConfirming(t.id)}><Trash2 size={rem(13)} /></IconButton>}
            </div>
          )
        })}
      </div>
      <div className="space-y-2">
        <SectionLabel count={groups.size}>Groups</SectionLabel>
        {allGroups.map((g) => {
          const below = new Set([g.id, ...childrenOf(g.id)])
          return <GroupRow key={g.id} group={g} parents={allGroups.filter((p) => !below.has(p.id))} confirming={confirming === g.id} onConfirm={() => setConfirming(g.id)} onCancel={() => setConfirming('')}
            onSave={(next) => void run(() => api.updateGroup(next))} onDelete={() => void run(() => api.deleteGroup(g.id))} />
        })}
        <form onSubmit={(e) => {
          e.preventDefault()
          const name = newGroup.trim()
          if (name) void run(async () => {
            await api.createGroup(name, 'blue', '')
            setNewGroup('')
          })
        }}><input aria-label="New group" className={inputClass} placeholder="new group" value={newGroup} onChange={(e) => setNewGroup(e.target.value)} /></form>
      </div>
    </Modal>
  )
}
