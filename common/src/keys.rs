//! X25519 key generation/derivation for AmneziaWG identities. Pure crypto, independent of the
//! netlink wire format `netlink::awg` talks (see `netlink::awg::decode_key` for that side) - plus
//! `get_or_create_secret_key`, the "read a private key from a Secret field, generate+persist one
//! on first boot" bootstrap every operator with a persistent identity needs.

/// Generates a fresh X25519 private key for an interface's first boot. Uses
/// `x25519_dalek::StaticSecret::random_from_rng` for correct RFC7748 clamping.
pub fn generate_private_key() -> [u8; 32] {
    use getrandom::{SysRng, rand_core::UnwrapErr};
    let mut rng = UnwrapErr(SysRng);
    x25519_dalek::StaticSecret::random_from_rng(&mut rng).to_bytes()
}

/// Derives the public key from a private key (`public = private * basepoint`). Never stored
/// independently - always computed from the private key.
pub fn derive_public_key(private_key: [u8; 32]) -> String {
    use base64::Engine;
    let secret = x25519_dalek::StaticSecret::from(private_key);
    let public = x25519_dalek::PublicKey::from(&secret);
    base64::engine::general_purpose::STANDARD.encode(public.to_bytes())
}

fn decode_entry(
    secret: &k8s_openapi::api::core::v1::Secret,
    field: &str,
) -> Option<anyhow::Result<[u8; 32]>> {
    let existing = secret.data.as_ref()?.get(field)?;
    Some(
        std::str::from_utf8(&existing.0)
            .map_err(anyhow::Error::from)
            .and_then(|b64| crate::netlink::awg::decode_key(b64.trim())),
    )
}

/// Generates a fresh private key and merge-patches it into `field` of an already-existing
/// `name` Secret. Shared by both `get_or_create_secret_key` call sites that find the Secret
/// present but missing this particular field: the normal "first time this field is read" case,
/// and the create-race loser whose winner didn't happen to write this exact field either (e.g.
/// mesh's per-node entries, sharing one Secret keyed by node label - unlike roadwarriors' single
/// shared field, where a 409 always means the field is already there).
async fn add_secret_key_entry(
    secrets: &kube::Api<k8s_openapi::api::core::v1::Secret>,
    name: &str,
    field: &str,
) -> anyhow::Result<[u8; 32]> {
    use base64::Engine;
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret;
    use kube::api::{Patch, PatchParams};

    let private = generate_private_key();
    let b64 = base64::engine::general_purpose::STANDARD.encode(private);
    // A hand-rolled `json!({ "data": { field: b64 } })` merge patch would send `b64` as a plain
    // JSON string; the API server base64-decodes any `Secret.data` value exactly once on the way
    // in (per the `[]byte` field contract), so the stored bytes would end up as the *raw* key
    // bytes, not the base64 text this function's read path expects back. Going through
    // `ByteString` makes serde apply that base64 encoding itself, matching what a later `get()`
    // decodes.
    let patch = Secret {
        data: Some([(field.to_string(), ByteString(b64.into_bytes()))].into()),
        ..Default::default()
    };
    secrets
        .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| {
            anyhow::anyhow!("failed to add generated private key to {name} Secret: {e}")
        })?;
    tracing::info!(
        name,
        field,
        "generated a new private key (no existing entry found)"
    );
    Ok(private)
}

/// Reads a private key from `field` of Secret `name` in `namespace`, generating and persisting a
/// fresh one on first boot. Every first-boot pod races to create the Secret at once; a 409 means
/// another pod's `create` already won, so the loser re-fetches rather than trusting its own
/// locally generated candidate - and, since the winner may have created the Secret with a
/// *different* field set (e.g. mesh's per-node entries sharing one Secret), falls through to the
/// same merge-patch path used when the Secret already existed without this field, instead of
/// assuming the field it wants is now there.
pub async fn get_or_create_secret_key(
    secrets: &kube::Api<k8s_openapi::api::core::v1::Secret>,
    namespace: &str,
    name: &str,
    field: &str,
) -> anyhow::Result<[u8; 32]> {
    use base64::Engine;
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::Secret;
    use kube::api::{ObjectMeta, PostParams};

    match secrets.get(name).await {
        Ok(secret) => match decode_entry(&secret, field) {
            Some(result) => result,
            None => add_secret_key_entry(secrets, name, field).await,
        },
        Err(kube::Error::Api(e)) if e.code == 404 => {
            let private = generate_private_key();
            let b64 = base64::engine::general_purpose::STANDARD.encode(private);
            let secret = Secret {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    namespace: Some(namespace.to_string()),
                    ..Default::default()
                },
                data: Some([(field.to_string(), ByteString(b64.into_bytes()))].into()),
                ..Default::default()
            };
            match secrets.create(&PostParams::default(), &secret).await {
                Ok(_) => {
                    tracing::info!(
                        name,
                        field,
                        "created Secret with a newly generated private key"
                    );
                    Ok(private)
                }
                Err(kube::Error::Api(e)) if e.code == 409 => {
                    let secret = secrets.get(name).await.map_err(|e| {
                        anyhow::anyhow!(
                            "failed to re-fetch {name} Secret after losing create race: {e}"
                        )
                    })?;
                    match decode_entry(&secret, field) {
                        Some(result) => result,
                        None => add_secret_key_entry(secrets, name, field).await,
                    }
                }
                Err(e) => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}
