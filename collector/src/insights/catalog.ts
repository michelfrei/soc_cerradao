import { z } from 'zod';

/**
 * Catálogo revisável de remediações. Um scid só é tratado como resolvível por
 * uma entrada quando aparece em configuration_ids (vínculo confirmado pela equipe).
 * name_hints apenas sugerem a entrada em blocos de investigação; nunca decidem.
 */
export const CATEGORIES = ['gpo_configuration', 'windows_update', 'application_update', 'driver_firmware',
  'software_replacement', 'script_manual', 'investigation'] as const;
export type Category = (typeof CATEGORIES)[number];

const Text = z.string().trim().min(1);

const GpoSetting = z.object({
  scope: z.enum(['computer', 'user']),
  path: Text,
  policy: Text,
  value: Text,
  registry: Text.nullable().default(null),
  os_requirements: Text.nullable().default(null),
  admx: Text.nullable().default(null),
});
export type GpoSettingConfig = z.infer<typeof GpoSetting>;

const ConfigurationEntry = z.object({
  key: z.string().regex(/^[a-z0-9-]+$/),
  title: Text,
  category: z.enum(['gpo_configuration', 'windows_update', 'script_manual']),
  remediation_type: z.enum(['definitive', 'mitigation']),
  configuration_ids: z.array(z.string().regex(/^scid-\d+$/)).default([]),
  name_hints: z.array(Text).default([]),
  gpo_name: Text.nullable().default(null),
  gpo_settings: z.array(GpoSetting).default([]),
  scope_guidance: Text.nullable().default(null),
  server_notes: Text.nullable().default(null),
  dc_notes: Text.nullable().default(null),
  compatibility_risks: z.array(Text).default([]),
  remediation_steps: z.array(Text).min(1),
  validation_steps: z.array(Text).min(1),
  rollback_steps: z.array(Text).min(1),
  dependencies: z.array(Text).default([]),
  references: z.array(z.string().url()).min(1),
  effort: z.enum(['baixo', 'medio', 'alto']),
  operational_impact: Text,
  owner: Text.optional(),
});
export type ConfigurationEntryConfig = z.infer<typeof ConfigurationEntry>;

/** Força a categoria de um software (ex.: firmware distribuído pelo fabricante). */
const SoftwareRule = z.object({
  vendor: Text.transform((v) => v.toLowerCase()),
  name_pattern: Text.refine((p) => { try { new RegExp(p); return true; } catch { return false; } }, 'regex inválida'),
  category: z.enum(['application_update', 'driver_firmware', 'software_replacement', 'script_manual']),
  note: Text,
  owner: Text.optional(),
});
export type SoftwareRuleConfig = z.infer<typeof SoftwareRule>;

const Catalog = z.object({
  owners: z.record(z.enum(CATEGORIES), Text).default({}),
  configurations: z.array(ConfigurationEntry).default([]),
  software_rules: z.array(SoftwareRule).default([]),
});
export type RemediationCatalog = z.infer<typeof Catalog>;

export const EMPTY_CATALOG: RemediationCatalog = { owners: {}, configurations: [], software_rules: [] };

export function parseCatalog(raw: unknown): RemediationCatalog {
  const catalog = Catalog.parse(raw);
  const keys = new Set<string>();
  const scids = new Map<string, string>();
  for (const entry of catalog.configurations) {
    if (keys.has(entry.key)) throw new Error(`catálogo: chave duplicada ${entry.key}`);
    keys.add(entry.key);
    if (entry.category === 'gpo_configuration' && (!entry.gpo_name || entry.gpo_settings.length === 0)) {
      throw new Error(`catálogo: ${entry.key} é gpo_configuration sem gpo_name/gpo_settings`);
    }
    for (const id of entry.configuration_ids) {
      const other = scids.get(id);
      if (other) throw new Error(`catálogo: ${id} vinculado a ${other} e ${entry.key}`);
      scids.set(id, entry.key);
    }
  }
  return catalog;
}
