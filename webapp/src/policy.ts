import { AttributeRuleTypeEnum, SubjectMappingOperatorEnum, ConditionBooleanTypeEnum } from '@opentdf/sdk';
import type { LabClients } from './tdf';

/**
 * Read-only view of the platform's policy, fetched with the signed-in user's
 * own token. Both user-a and user-b hold the realm role `opentdf-standard`, which
 * the platform maps onto casbin `role:standard` - enough to read policy, not
 * enough to change it. Every write path is deliberately absent from this
 * console.
 */

export type PolicyValue = { id: string; value: string; fqn: string; active: boolean };

export type PolicyAttribute = {
  id: string;
  name: string;
  fqn: string;
  rule: string;
  namespaceName: string;
  active: boolean;
  values: PolicyValue[];
};

export type PolicyNamespace = { id: string; name: string; fqn: string; active: boolean };

export type PolicyCondition = {
  selector: string;
  operator: string;
  values: string[];
};

export type PolicySubjectMapping = {
  id: string;
  valueFqn: string;
  value: string;
  actions: string[];
  booleanOperator: string;
  conditions: PolicyCondition[];
};

export type PolicyKas = { id: string; uri: string; name: string };

export type PolicySnapshot = {
  namespaces: PolicyNamespace[];
  attributes: PolicyAttribute[];
  subjectMappings: PolicySubjectMapping[];
  kasRegistry: PolicyKas[];
  fetchedAt: number;
};

/** protobuf-es hands back numeric enum members; these give them their names back. */
function ruleName(rule: number | undefined): string {
  switch (rule) {
    case AttributeRuleTypeEnum.ALL_OF: return 'ALL_OF';
    case AttributeRuleTypeEnum.ANY_OF: return 'ANY_OF';
    case AttributeRuleTypeEnum.HIERARCHY: return 'HIERARCHY';
    default: return 'UNSPECIFIED';
  }
}

function operatorName(op: number | undefined): string {
  switch (op) {
    case SubjectMappingOperatorEnum.IN: return 'IN';
    case SubjectMappingOperatorEnum.NOT_IN: return 'NOT IN';
    case SubjectMappingOperatorEnum.IN_CONTAINS: return 'CONTAINS';
    default: return 'UNSPECIFIED';
  }
}

function booleanName(op: number | undefined): string {
  switch (op) {
    case ConditionBooleanTypeEnum.AND: return 'AND';
    case ConditionBooleanTypeEnum.OR: return 'OR';
    default: return 'UNSPECIFIED';
  }
}

export async function fetchPolicy(clients: LabClients): Promise<PolicySnapshot> {
  const [namespacesRes, attributesRes, mappingsRes, kasRes] = await Promise.all([
    clients.platform.v1.namespace.listNamespaces({}),
    clients.platform.v1.attributes.listAttributes({}),
    clients.platform.v1.subjectMapping.listSubjectMappings({}),
    clients.platform.v1.keyAccessServerRegistry.listKeyAccessServers({}),
  ]);

  const namespaces: PolicyNamespace[] = namespacesRes.namespaces.map((n) => ({
    id: n.id,
    name: n.name,
    fqn: n.fqn,
    active: n.active ?? true,
  }));

  const attributes: PolicyAttribute[] = attributesRes.attributes.map((a) => ({
    id: a.id,
    name: a.name,
    fqn: a.fqn,
    rule: ruleName(a.rule),
    namespaceName: a.namespace?.name ?? '',
    active: a.active ?? true,
    values: a.values.map((v) => ({
      id: v.id,
      value: v.value,
      fqn: v.fqn,
      active: v.active ?? true,
    })),
  }));

  const subjectMappings: PolicySubjectMapping[] = mappingsRes.subjectMappings.map((m) => {
    const group = m.subjectConditionSet?.subjectSets?.[0]?.conditionGroups?.[0];
    return {
      id: m.id,
      valueFqn: m.attributeValue?.fqn ?? '',
      value: m.attributeValue?.value ?? '',
      actions: m.actions.map((act) => act.name).filter(Boolean),
      booleanOperator: booleanName(group?.booleanOperator),
      conditions: (group?.conditions ?? []).map((c) => ({
        selector: c.subjectExternalSelectorValue,
        operator: operatorName(c.operator),
        values: c.subjectExternalValues,
      })),
    };
  });

  const kasRegistry: PolicyKas[] = kasRes.keyAccessServers.map((k) => ({
    id: k.id,
    uri: k.uri,
    name: k.name,
  }));

  return { namespaces, attributes, subjectMappings, kasRegistry, fetchedAt: Date.now() };
}

/** Every attribute value FQN, flattened, for the encrypt picker. */
export function allValues(snapshot: PolicySnapshot | null): { fqn: string; label: string; attribute: string; rule: string }[] {
  if (!snapshot) return [];
  return snapshot.attributes.flatMap((a) =>
    a.values
      .filter((v) => v.active)
      .map((v) => ({ fqn: v.fqn, label: v.value, attribute: a.name, rule: a.rule })),
  );
}
