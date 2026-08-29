use crate::root_protocol::AuthenticatedActorSnapshotV1;
use crate::root_protocol::RootMethodV1;
use crate::root_protocol::RootProtocolError;
use crate::root_protocol::admit_root_command;
use crate::root_store::RootStore;
use crate::root_store::RootStoreBootstrapV1;
use crate::root_store::RootStoreError;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[cfg(test)]
#[path = "root_service_fake_effect.rs"]
mod fake_effect;
#[cfg(test)]
pub(crate) use fake_effect::execute_synthetic_effect_for_test;

pub(crate) const SYNTHETIC_ROOT_QUEUE_CAPACITY: usize = 128;
const SYNTHETIC_ROOT_REPLY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SyntheticRootServiceErrorV1 {
    Protocol(RootProtocolError),
    Store(RootStoreError),
    MethodUnavailable,
    ServiceBusy,
    ReplyTimedOut,
    ServiceStopped,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SyntheticRootReplyV1 {
    Revision(u64),
    ExecuteNow(SyntheticExecuteNowDispositionV1),
    BrokerState {
        state: String,
        revision: u64,
        effect_attempt_count: u64,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct SyntheticExecuteNowDispositionV1 {
    operation_id: String,
    revision: u64,
    effect_request_digest: String,
}

impl SyntheticExecuteNowDispositionV1 {
    fn into_effect_invocation(self) -> (String, u64, String) {
        (self.operation_id, self.revision, self.effect_request_digest)
    }
}

enum ServiceRequest {
    Command {
        actor: AuthenticatedActorSnapshotV1,
        exact_message: Box<[u8]>,
        reply: mpsc::SyncSender<Result<SyntheticRootReplyV1, SyntheticRootServiceErrorV1>>,
    },
    GuardInternalBeginQuiesce {
        expected_release_sequence: u64,
        expected_revision: u64,
        reply: mpsc::SyncSender<Result<u64, RootStoreError>>,
    },
    GuardInternalActivate {
        expected_release_sequence: u64,
        expected_revision: u64,
        next: RootStoreBootstrapV1,
        reply: mpsc::SyncSender<Result<u64, RootStoreError>>,
    },
    #[cfg(test)]
    Pause {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    },
    Stop,
}

#[derive(Clone)]
pub(crate) struct SyntheticRootServiceClientV1 {
    sender: mpsc::SyncSender<ServiceRequest>,
}

impl SyntheticRootServiceClientV1 {
    pub(crate) fn dispatch(
        &self,
        actor: AuthenticatedActorSnapshotV1,
        exact_message: Box<[u8]>,
    ) -> Result<SyntheticRootReplyV1, SyntheticRootServiceErrorV1> {
        self.dispatch_with_timeout(actor, exact_message, SYNTHETIC_ROOT_REPLY_TIMEOUT)
    }

    fn dispatch_with_timeout(
        &self,
        actor: AuthenticatedActorSnapshotV1,
        exact_message: Box<[u8]>,
        timeout: Duration,
    ) -> Result<SyntheticRootReplyV1, SyntheticRootServiceErrorV1> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(ServiceRequest::Command {
                actor,
                exact_message,
                reply,
            })
            .map_err(map_try_send_error)?;
        match receiver.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(SyntheticRootServiceErrorV1::ReplyTimedOut),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(SyntheticRootServiceErrorV1::ServiceStopped)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn enqueue_for_test(
        &self,
        actor: AuthenticatedActorSnapshotV1,
        exact_message: Box<[u8]>,
    ) -> Result<
        mpsc::Receiver<Result<SyntheticRootReplyV1, SyntheticRootServiceErrorV1>>,
        SyntheticRootServiceErrorV1,
    > {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(ServiceRequest::Command {
                actor,
                exact_message,
                reply,
            })
            .map_err(map_try_send_error)?;
        Ok(receiver)
    }
}

pub(crate) struct SyntheticRootServiceV1 {
    client: SyntheticRootServiceClientV1,
    join: Option<thread::JoinHandle<()>>,
}

impl SyntheticRootServiceV1 {
    pub(crate) fn start(
        root: PathBuf,
        bootstrap: RootStoreBootstrapV1,
    ) -> Result<Self, RootStoreError> {
        let (sender, receiver) = mpsc::sync_channel(SYNTHETIC_ROOT_QUEUE_CAPACITY);
        let (ready, ready_receiver) = mpsc::sync_channel(1);
        let join = thread::spawn(move || {
            let mut store = match RootStore::open(&root, &bootstrap) {
                Ok(store) => {
                    let _ = ready.send(Ok(()));
                    store
                }
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            loop {
                match receiver.recv() {
                    Ok(ServiceRequest::Command {
                        actor,
                        exact_message,
                        reply,
                    }) => {
                        let result = dispatch_raw_message(&mut store, actor, exact_message);
                        let _ = reply.send(result);
                    }
                    Ok(ServiceRequest::GuardInternalBeginQuiesce {
                        expected_release_sequence,
                        expected_revision,
                        reply,
                    }) => {
                        let _ = reply.send(
                            store.begin_quiesce(expected_release_sequence, expected_revision),
                        );
                    }
                    Ok(ServiceRequest::GuardInternalActivate {
                        expected_release_sequence,
                        expected_revision,
                        next,
                        reply,
                    }) => {
                        let _ = reply.send(store.activate_release(
                            expected_release_sequence,
                            expected_revision,
                            &next,
                        ));
                    }
                    #[cfg(test)]
                    Ok(ServiceRequest::Pause { entered, release }) => {
                        let _ = entered.send(());
                        let _ = release.recv();
                    }
                    Ok(ServiceRequest::Stop) | Err(_) => return,
                }
            }
        });
        match ready_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                client: SyntheticRootServiceClientV1 { sender },
                join: Some(join),
            }),
            Ok(Err(error)) => {
                let _ = join.join();
                Err(error)
            }
            Err(_) => {
                let _ = join.join();
                Err(RootStoreError::Integrity(
                    "synthetic root service stopped during startup".to_string(),
                ))
            }
        }
    }

    pub(crate) fn client(&self) -> SyntheticRootServiceClientV1 {
        self.client.clone()
    }

    #[cfg(test)]
    pub(crate) fn enqueue_begin_quiesce_for_test(
        &self,
        expected_release_sequence: u64,
        expected_revision: u64,
    ) -> Result<mpsc::Receiver<Result<u64, RootStoreError>>, RootStoreError> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.client
            .sender
            .send(ServiceRequest::GuardInternalBeginQuiesce {
                expected_release_sequence,
                expected_revision,
                reply,
            })
            .map_err(|_| RootStoreError::Integrity("root service stopped".to_string()))?;
        Ok(receiver)
    }

    #[cfg(test)]
    pub(crate) fn activate_internal(
        &self,
        expected_release_sequence: u64,
        expected_revision: u64,
        next: RootStoreBootstrapV1,
    ) -> Result<u64, RootStoreError> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.client
            .sender
            .send(ServiceRequest::GuardInternalActivate {
                expected_release_sequence,
                expected_revision,
                next,
                reply,
            })
            .map_err(|_| RootStoreError::Integrity("root service stopped".to_string()))?;
        receive_internal_reply(receiver)
    }

    #[cfg(test)]
    pub(crate) fn pause_for_test(&self) -> mpsc::SyncSender<()> {
        let (entered, entered_receiver) = mpsc::sync_channel(1);
        let (release, release_receiver) = mpsc::sync_channel(1);
        self.client
            .sender
            .send(ServiceRequest::Pause {
                entered,
                release: release_receiver,
            })
            .expect("synthetic root control channel");
        entered_receiver
            .recv()
            .expect("synthetic root service paused");
        release
    }
}

impl Drop for SyntheticRootServiceV1 {
    fn drop(&mut self) {
        let _ = self.client.sender.send(ServiceRequest::Stop);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn map_try_send_error(error: mpsc::TrySendError<ServiceRequest>) -> SyntheticRootServiceErrorV1 {
    match error {
        mpsc::TrySendError::Full(_) => SyntheticRootServiceErrorV1::ServiceBusy,
        mpsc::TrySendError::Disconnected(_) => SyntheticRootServiceErrorV1::ServiceStopped,
    }
}

fn receive_internal_reply(
    receiver: mpsc::Receiver<Result<u64, RootStoreError>>,
) -> Result<u64, RootStoreError> {
    match receiver.recv_timeout(SYNTHETIC_ROOT_REPLY_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(RootStoreError::Integrity(
            "synthetic root service reply timed out".to_string(),
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(RootStoreError::Integrity(
            "synthetic root service stopped".to_string(),
        )),
    }
}

fn dispatch_raw_message(
    store: &mut RootStore,
    actor: AuthenticatedActorSnapshotV1,
    exact_message: Box<[u8]>,
) -> Result<SyntheticRootReplyV1, SyntheticRootServiceErrorV1> {
    let authorized =
        admit_root_command(actor, &exact_message).map_err(SyntheticRootServiceErrorV1::Protocol)?;
    match authorized.command().method() {
        RootMethodV1::BrokerAuthorize => store
            .authorize_broker(authorized)
            .map(SyntheticRootReplyV1::Revision)
            .map_err(SyntheticRootServiceErrorV1::Store),
        RootMethodV1::BrokerCancelBeforeClaim => store
            .cancel_before_claim(authorized)
            .map(SyntheticRootReplyV1::Revision)
            .map_err(SyntheticRootServiceErrorV1::Store),
        RootMethodV1::BrokerClaim => store
            .claim_broker(authorized)
            .map(SyntheticRootReplyV1::Revision)
            .map_err(SyntheticRootServiceErrorV1::Store),
        RootMethodV1::BrokerEffectStart => store
            .start_broker_effect(authorized)
            .map(|disposition| {
                let (operation_id, revision, effect_request_digest) = disposition.into_parts();
                SyntheticRootReplyV1::ExecuteNow(SyntheticExecuteNowDispositionV1 {
                    operation_id,
                    revision,
                    effect_request_digest,
                })
            })
            .map_err(SyntheticRootServiceErrorV1::Store),
        RootMethodV1::BrokerQuery => store
            .query_broker(authorized)
            .map(|view| SyntheticRootReplyV1::BrokerState {
                state: view.state,
                revision: view.revision,
                effect_attempt_count: view.effect_attempt_count,
            })
            .map_err(SyntheticRootServiceErrorV1::Store),
        RootMethodV1::BrokerSettle
        | RootMethodV1::LaunchPrepare
        | RootMethodV1::LaunchStart
        | RootMethodV1::LaunchCancel
        | RootMethodV1::LaunchQuery
        | RootMethodV1::ReleaseOfferVendorMetadata
        | RootMethodV1::ReleaseQueryStatus
        | RootMethodV1::PublicStatus => Err(SyntheticRootServiceErrorV1::MethodUnavailable),
    }
}
