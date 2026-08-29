use super::*;

const WORLD: &str = r#"{"runtimeRead":true,"sessionWrite":true,"workspaceRead":false,"workspaceWrite":false,"homeRead":false,"sshRead":false,"keychainRead":false,"rbStateRead":false,"siblingRead":false,"sharedTmpWrite":false,"tcp4":false,"tcp6":false,"udp":false,"dns":false,"namedUnix":false,"shell":false,"machSecurityd":false}"#;

fn valid_protocol() -> String {
    [
        "LAUNCH_FD_INVENTORY|0,1,2,20".to_string(),
        "BOOTSTRAP|pid=4312|selfexec=false".to_string(),
        format!("WORLD|actor=parent|{WORLD}"),
        "DIRECT|actor=parent|pty=false|shm=false|sem=false".to_string(),
        format!("WORKER|result={WORLD}"),
        "SPAWN|status=undefined|signal=null|error=Error|stdout=null".to_string(),
        "SELFEXEC_CALL".to_string(),
        "BOOTSTRAP|pid=4312|selfexec=true".to_string(),
        format!("WORLD|actor=selfexec|{WORLD}"),
        "DIRECT|actor=selfexec|pty=false|shm=false|sem=false".to_string(),
        "NONEXACT_EXEC_ATTEMPT|path=/usr/bin/true".to_string(),
        "NONEXACT_EXEC_DENIED|errno=-1".to_string(),
    ]
    .join("\n")
}

#[test]
fn verifies_exact_positive_and_forbidden_world_contract() {
    let verified = verify_rb_outer_omp_world_protocol(valid_protocol().as_bytes())
        .expect("valid world protocol");
    assert_eq!(verified.pid, 4312);
    assert_eq!(
        verified.actors,
        ["parent", "worker", "selfexec"]
            .into_iter()
            .map(str::to_string)
            .collect()
    );
}

#[test]
fn rejects_forbidden_effect_missing_actor_and_structural_drift() {
    let valid = valid_protocol();
    let forbidden = valid.replacen("\"keychainRead\":false", "\"keychainRead\":true", 1);
    assert!(matches!(
        verify_rb_outer_omp_world_protocol(forbidden.as_bytes()),
        Err(RbOuterOmpWorldVerificationError::InvalidWorld {
            actor: "parent",
            ..
        })
    ));

    let missing = valid
        .lines()
        .filter(|line| !line.starts_with("WORKER|"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(matches!(
        verify_rb_outer_omp_world_protocol(missing.as_bytes()),
        Err(RbOuterOmpWorldVerificationError::UnexpectedLine { .. })
    ));

    let extra_field = valid.replacen(
        "\"machSecurityd\":false}",
        "\"machSecurityd\":false,\"unexpected\":false}",
        1,
    );
    assert!(matches!(
        verify_rb_outer_omp_world_protocol(extra_field.as_bytes()),
        Err(RbOuterOmpWorldVerificationError::InvalidWorld {
            actor: "parent",
            ..
        })
    ));
}

#[test]
fn rejects_loader_silence_duplicate_records_pid_change_and_oversize() {
    assert!(verify_rb_outer_omp_world_protocol(b"").is_err());

    let valid = valid_protocol();
    let duplicate = format!("{valid}\nSELFEXEC_CALL");
    assert!(verify_rb_outer_omp_world_protocol(duplicate.as_bytes()).is_err());

    let changed_pid = valid.replacen(
        "BOOTSTRAP|pid=4312|selfexec=true",
        "BOOTSTRAP|pid=4313|selfexec=true",
        1,
    );
    assert_eq!(
        verify_rb_outer_omp_world_protocol(changed_pid.as_bytes()),
        Err(RbOuterOmpWorldVerificationError::SelfExecChangedPid {
            parent: 4312,
            self_exec: 4313,
        })
    );

    assert_eq!(
        verify_rb_outer_omp_world_protocol(&vec![b'x'; MAX_PROTOCOL_BYTES + 1]),
        Err(RbOuterOmpWorldVerificationError::Oversized)
    );
}
