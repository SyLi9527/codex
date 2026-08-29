use crate::root_protocol::ActorRoleV1;
use crate::root_protocol::AuthorizedRootCommandV1;
use crate::root_protocol::RootMethodV1;
use crate::root_protocol::revalidate_authorized_command;
use crate::root_sqlite::SqlValue;
use crate::root_store::RootStore;
use crate::root_store::RootStoreError;

pub(crate) struct ExecuteNowDispositionV1 {
    operation_id: String,
    revision: u64,
    effect_request_digest: String,
}

impl ExecuteNowDispositionV1 {
    pub(crate) fn into_parts(self) -> (String, u64, String) {
        (self.operation_id, self.revision, self.effect_request_digest)
    }

    #[cfg(test)]
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[cfg(test)]
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    #[cfg(test)]
    pub(crate) fn effect_request_digest(&self) -> &str {
        &self.effect_request_digest
    }
}

pub(crate) struct GuardVerifiedEffectReceiptV1 {
    operation_id: String,
    owner_instance: String,
    evidence_digest: String,
}

impl GuardVerifiedEffectReceiptV1 {
    #[cfg(test)]
    pub(crate) fn new_for_test(
        operation_id: String,
        owner_instance: String,
        evidence_digest: String,
    ) -> Self {
        Self {
            operation_id,
            owner_instance,
            evidence_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BrokerOperationViewV1 {
    pub(crate) state: String,
    pub(crate) revision: u64,
    pub(crate) effect_attempt_count: u64,
}

impl RootStore {
    pub(crate) fn authorize_broker(
        &mut self,
        authorized: AuthorizedRootCommandV1,
    ) -> Result<u64, RootStoreError> {
        require_method(&authorized, RootMethodV1::BrokerAuthorize)?;
        self.transaction(|store| {
            let state = store.release_state()?;
            store.revalidate_actor(&authorized, &state)?;
            if state.lifecycle != "active" {
                return Err(RootStoreError::Quiescing);
            }
            if authorized.command().expected_revision() != 0 {
                return Err(RootStoreError::RevisionMismatch);
            }
            if store.db.query_i64(
                "SELECT COUNT(*) FROM broker_operations WHERE operation_id=?",
                &[SqlValue::Text(authorized.command().operation_id())],
            )? != 0
            {
                return Err(RootStoreError::InvalidTransition);
            }
            let broker_role = authorized
                .command()
                .broker_role()
                .ok_or(RootStoreError::MethodMismatch)?;
            store.db.execute(
                "INSERT INTO broker_operations(operation_id,authorizing_gateway_tuple_digest,subject_digest,payload_digest,broker_role,release_sequence,lease_epoch,state,effect_attempt_count,owner_instance,revision) VALUES(?,?,?,?,?,?,?,'authorized',0,NULL,1)",
                &[
                    SqlValue::Text(authorized.command().operation_id()),
                    SqlValue::Text(authorized.actor().component_tuple_digest()),
                    SqlValue::Text(authorized.command().subject_digest()),
                    SqlValue::Text(authorized.command().payload_digest()),
                    SqlValue::Text(broker_role.as_str()),
                    SqlValue::Integer(to_i64(state.release_sequence)?),
                    SqlValue::Integer(to_i64(state.lease_epoch)?),
                ],
            )?;
            Ok(1)
        })
    }

    pub(crate) fn cancel_before_claim(
        &mut self,
        authorized: AuthorizedRootCommandV1,
    ) -> Result<u64, RootStoreError> {
        require_method(&authorized, RootMethodV1::BrokerCancelBeforeClaim)?;
        self.transaction(|store| {
            let state = store.release_state()?;
            store.revalidate_actor(&authorized, &state)?;
            let changed = store.db.execute(
                "UPDATE broker_operations SET state='cancelled-no-effect',revision=revision+1 WHERE operation_id=? AND authorizing_gateway_tuple_digest=? AND subject_digest=? AND payload_digest=? AND broker_role=? AND release_sequence=? AND lease_epoch=? AND state='authorized' AND effect_attempt_count=0 AND revision=?",
                &operation_owner_params(&authorized)?,
            )?;
            changed_revision(changed, authorized.command().expected_revision())
        })
    }

    pub(crate) fn claim_broker(
        &mut self,
        authorized: AuthorizedRootCommandV1,
    ) -> Result<u64, RootStoreError> {
        require_method(&authorized, RootMethodV1::BrokerClaim)?;
        self.transaction(|store| {
            let state = store.release_state()?;
            store.revalidate_actor(&authorized, &state)?;
            if state.lifecycle != "active" {
                return Err(RootStoreError::Quiescing);
            }
            let changed = store.db.execute(
                "UPDATE broker_operations SET state='claimed',owner_instance=?,revision=revision+1 WHERE operation_id=? AND subject_digest=? AND payload_digest=? AND broker_role=? AND release_sequence=? AND lease_epoch=? AND state='authorized' AND effect_attempt_count=0 AND revision=?",
                &[
                    SqlValue::Text(authorized.actor().connection_instance()),
                    SqlValue::Text(authorized.command().operation_id()),
                    SqlValue::Text(authorized.command().subject_digest()),
                    SqlValue::Text(authorized.command().payload_digest()),
                    SqlValue::Text(broker_role(&authorized)?),
                    SqlValue::Integer(to_i64(state.release_sequence)?),
                    SqlValue::Integer(to_i64(state.lease_epoch)?),
                    SqlValue::Integer(to_i64(authorized.command().expected_revision())?),
                ],
            )?;
            changed_revision(changed, authorized.command().expected_revision())
        })
    }

    pub(crate) fn start_broker_effect(
        &mut self,
        authorized: AuthorizedRootCommandV1,
    ) -> Result<ExecuteNowDispositionV1, RootStoreError> {
        require_method(&authorized, RootMethodV1::BrokerEffectStart)?;
        self.transaction(|store| {
            let state = store.release_state()?;
            store.revalidate_actor(&authorized, &state)?;
            if state.lifecycle != "active" {
                return Err(RootStoreError::Quiescing);
            }
            let changed = store.db.execute(
                "UPDATE broker_operations SET state='effect-starting',effect_attempt_count=1,revision=revision+1 WHERE operation_id=? AND subject_digest=? AND payload_digest=? AND broker_role=? AND owner_instance=? AND release_sequence=? AND lease_epoch=? AND state='claimed' AND effect_attempt_count=0 AND revision=?",
                &[
                    SqlValue::Text(authorized.command().operation_id()),
                    SqlValue::Text(authorized.command().subject_digest()),
                    SqlValue::Text(authorized.command().payload_digest()),
                    SqlValue::Text(broker_role(&authorized)?),
                    SqlValue::Text(authorized.actor().connection_instance()),
                    SqlValue::Integer(to_i64(state.release_sequence)?),
                    SqlValue::Integer(to_i64(state.lease_epoch)?),
                    SqlValue::Integer(to_i64(authorized.command().expected_revision())?),
                ],
            )?;
            let revision = changed_revision(changed, authorized.command().expected_revision())?;
            Ok(ExecuteNowDispositionV1 {
                operation_id: authorized.command().operation_id().to_string(),
                revision,
                effect_request_digest: authorized.command().payload_digest().to_string(),
            })
        })
    }

    pub(crate) fn settle_broker_safe(
        &mut self,
        authorized: AuthorizedRootCommandV1,
        receipt: GuardVerifiedEffectReceiptV1,
    ) -> Result<u64, RootStoreError> {
        require_method(&authorized, RootMethodV1::BrokerSettle)?;
        if receipt.operation_id != authorized.command().operation_id()
            || receipt.owner_instance != authorized.actor().connection_instance()
            || receipt.evidence_digest != authorized.command().payload_digest()
        {
            return Err(RootStoreError::InvalidTransition);
        }
        self.transaction(|store| {
            let state = store.release_state()?;
            store.revalidate_actor(&authorized, &state)?;
            let changed = store.db.execute(
                "UPDATE broker_operations SET state='settled-safe',settlement_digest=?,revision=revision+1 WHERE operation_id=? AND subject_digest=? AND broker_role=? AND owner_instance=? AND release_sequence=? AND lease_epoch=? AND state='effect-starting' AND effect_attempt_count=1 AND revision=?",
                &[
                    SqlValue::Text(&receipt.evidence_digest),
                    SqlValue::Text(authorized.command().operation_id()),
                    SqlValue::Text(authorized.command().subject_digest()),
                    SqlValue::Text(broker_role(&authorized)?),
                    SqlValue::Text(authorized.actor().connection_instance()),
                    SqlValue::Integer(to_i64(state.release_sequence)?),
                    SqlValue::Integer(to_i64(state.lease_epoch)?),
                    SqlValue::Integer(to_i64(authorized.command().expected_revision())?),
                ],
            )?;
            changed_revision(changed, authorized.command().expected_revision())
        })
    }

    pub(crate) fn mark_broker_effect_unknown(
        &mut self,
        operation_id: &str,
        expected_revision: u64,
    ) -> Result<u64, RootStoreError> {
        self.transaction(|store| {
            let changed = store.db.execute(
                "UPDATE broker_operations SET state='effect-unknown',revision=revision+1 WHERE operation_id=? AND state='effect-starting' AND effect_attempt_count=1 AND revision=?",
                &[
                    SqlValue::Text(operation_id),
                    SqlValue::Integer(to_i64(expected_revision)?),
                ],
            )?;
            changed_revision(changed, expected_revision)
        })
    }

    pub(crate) fn query_broker(
        &mut self,
        authorized: AuthorizedRootCommandV1,
    ) -> Result<BrokerOperationViewV1, RootStoreError> {
        require_method(&authorized, RootMethodV1::BrokerQuery)?;
        self.transaction(|store| {
            let state = store.release_state()?;
            store.revalidate_actor(&authorized, &state)?;
            let role = broker_role(&authorized)?;
            let state = if authorized.actor().role() == ActorRoleV1::Gateway {
                store.db.query_broker_view(
                    "SELECT state,revision,effect_attempt_count FROM broker_operations WHERE operation_id=? AND subject_digest=? AND payload_digest=? AND broker_role=? AND authorizing_gateway_tuple_digest=? AND release_sequence=? AND lease_epoch=?",
                    &[
                        SqlValue::Text(authorized.command().operation_id()),
                        SqlValue::Text(authorized.command().subject_digest()),
                        SqlValue::Text(authorized.command().payload_digest()),
                        SqlValue::Text(role),
                        SqlValue::Text(authorized.actor().component_tuple_digest()),
                        SqlValue::Integer(to_i64(state.release_sequence)?),
                        SqlValue::Integer(to_i64(state.lease_epoch)?),
                    ],
                )?
            } else {
                store.db.query_broker_view(
                    "SELECT state,revision,effect_attempt_count FROM broker_operations WHERE operation_id=? AND subject_digest=? AND broker_role=? AND owner_instance=? AND release_sequence=? AND lease_epoch=?",
                    &[
                        SqlValue::Text(authorized.command().operation_id()),
                        SqlValue::Text(authorized.command().subject_digest()),
                        SqlValue::Text(role),
                        SqlValue::Text(authorized.actor().connection_instance()),
                        SqlValue::Integer(to_i64(state.release_sequence)?),
                        SqlValue::Integer(to_i64(state.lease_epoch)?),
                    ],
                )?
            };
            Ok(BrokerOperationViewV1 {
                state: state.0,
                revision: to_u64(state.1)?,
                effect_attempt_count: to_u64(state.2)?,
            })
        })
    }
}

fn require_method(
    authorized: &AuthorizedRootCommandV1,
    method: RootMethodV1,
) -> Result<(), RootStoreError> {
    if authorized.command().method() != method {
        return Err(RootStoreError::MethodMismatch);
    }
    revalidate_authorized_command(authorized)
        .map_err(|error| RootStoreError::Integrity(format!("actor ACL drift: {error:?}")))
}

fn broker_role(authorized: &AuthorizedRootCommandV1) -> Result<&'static str, RootStoreError> {
    Ok(authorized
        .command()
        .broker_role()
        .ok_or(RootStoreError::MethodMismatch)?
        .as_str())
}

fn operation_owner_params<'a>(
    authorized: &'a AuthorizedRootCommandV1,
) -> Result<[SqlValue<'a>; 8], RootStoreError> {
    Ok([
        SqlValue::Text(authorized.command().operation_id()),
        SqlValue::Text(authorized.actor().component_tuple_digest()),
        SqlValue::Text(authorized.command().subject_digest()),
        SqlValue::Text(authorized.command().payload_digest()),
        SqlValue::Text(broker_role(authorized)?),
        SqlValue::Integer(to_i64(authorized.actor().release_sequence())?),
        SqlValue::Integer(to_i64(authorized.actor().lease_epoch())?),
        SqlValue::Integer(to_i64(authorized.command().expected_revision())?),
    ])
}

fn changed_revision(changed: usize, expected_revision: u64) -> Result<u64, RootStoreError> {
    if changed != 1 {
        return Err(RootStoreError::InvalidTransition);
    }
    expected_revision
        .checked_add(1)
        .ok_or(RootStoreError::InvalidTransition)
}

fn to_i64(value: u64) -> Result<i64, RootStoreError> {
    i64::try_from(value).map_err(|_| RootStoreError::InvalidTransition)
}

fn to_u64(value: i64) -> Result<u64, RootStoreError> {
    u64::try_from(value).map_err(|_| RootStoreError::Integrity("negative integer".to_string()))
}
