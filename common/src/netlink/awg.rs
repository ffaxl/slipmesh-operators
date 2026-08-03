//! Thin wrapper around `netlink-packet-amnezia-wireguard` + `genetlink` - talks the kernel
//! module's own genl family ("amneziawg", not "wireguard") directly rather than shelling out to
//! the `awg` CLI. Used by both mesh and roadwarriors, which each build their own domain-specific
//! device/peer attribute lists on top of this; this module only owns the raw
//! `GetDevice`/`SetDevice` netlink transport. Interface/address/route management is `rt.rs`
//! (a different netlink family).

use crate::mesh_types::Obfuscation;
use anyhow::{Context, Result};
use futures::StreamExt;
use genetlink::GenetlinkHandle;
use netlink_packet_amnezia_wireguard::{
    AmneziaWireguardAttribute, AmneziaWireguardCmd, AmneziaWireguardMessage,
};
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;

/// Decodes a base64-encoded AmneziaWG key (private or public - the wire format doesn't
/// distinguish) into the raw 32 bytes `AmneziaWireguardAttribute::PrivateKey`/`PublicKey` expect.
pub fn decode_key(b64: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("invalid base64 key")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key is not 32 bytes"))
}

/// Appends the device-level attributes for whichever of `Obfuscation`'s nine fields are set -
/// omitted fields are left unmentioned (not sent as zero/default), matching AmneziaWG's own
/// "unset means kernel module default" semantics.
pub fn push_obfuscation_attrs(attrs: &mut Vec<AmneziaWireguardAttribute>, o: &Obfuscation) {
    if let Some(v) = o.jc {
        attrs.push(AmneziaWireguardAttribute::JC(v));
    }
    if let Some(v) = o.jmin {
        attrs.push(AmneziaWireguardAttribute::Jmin(v));
    }
    if let Some(v) = o.jmax {
        attrs.push(AmneziaWireguardAttribute::Jmax(v));
    }
    if let Some(v) = o.s1 {
        attrs.push(AmneziaWireguardAttribute::S1(v));
    }
    if let Some(v) = o.s2 {
        attrs.push(AmneziaWireguardAttribute::S2(v));
    }
    if let Some(v) = o.h1 {
        attrs.push(AmneziaWireguardAttribute::H1(v.to_string()));
    }
    if let Some(v) = o.h2 {
        attrs.push(AmneziaWireguardAttribute::H2(v.to_string()));
    }
    if let Some(v) = o.h3 {
        attrs.push(AmneziaWireguardAttribute::H3(v.to_string()));
    }
    if let Some(v) = o.h4 {
        attrs.push(AmneziaWireguardAttribute::H4(v.to_string()));
    }
}

#[derive(Clone)]
pub struct AwgClient {
    handle: GenetlinkHandle,
}

impl AwgClient {
    pub fn connect() -> Result<Self> {
        let (connection, handle, _) =
            genetlink::new_connection().context("failed to open genetlink socket")?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    pub async fn get_device(&mut self, ifname: &str) -> Result<Vec<AmneziaWireguardAttribute>> {
        let msg = AmneziaWireguardMessage {
            cmd: AmneziaWireguardCmd::GetDevice,
            attributes: vec![AmneziaWireguardAttribute::IfName(ifname.to_string())],
        };
        let genlmsg: GenlMessage<AmneziaWireguardMessage> = GenlMessage::from_payload(msg);
        let mut nlmsg = NetlinkMessage::from(genlmsg);
        nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        let mut res = self
            .handle
            .request(nlmsg)
            .await
            .context("genetlink GetDevice request failed")?;

        let mut attrs = Vec::new();
        while let Some(result) = res.next().await {
            let rx_packet = result.context("genetlink response error")?;
            match rx_packet.payload {
                NetlinkPayload::InnerMessage(genlmsg) => attrs.extend(genlmsg.payload.attributes),
                NetlinkPayload::Error(e) => {
                    anyhow::bail!("GetDevice({ifname}) netlink error: {:?}", e.to_io())
                }
                _ => {}
            }
        }
        Ok(attrs)
    }

    pub async fn set_device(&mut self, attributes: Vec<AmneziaWireguardAttribute>) -> Result<()> {
        let msg = AmneziaWireguardMessage {
            cmd: AmneziaWireguardCmd::SetDevice,
            attributes,
        };
        let genlmsg: GenlMessage<AmneziaWireguardMessage> = GenlMessage::from_payload(msg);
        let mut nlmsg = NetlinkMessage::from(genlmsg);
        nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut res = self
            .handle
            .request(nlmsg)
            .await
            .context("genetlink SetDevice request failed")?;
        // This amneziawg kernel module doesn't always send a response despite NLM_F_ACK - an
        // empty stream is logged, not treated as failure.
        match res.next().await {
            Some(result) => {
                let rx_packet = result.context("genetlink response error")?;
                if let NetlinkPayload::Error(e) = rx_packet.payload {
                    // `code: None` means ACK per RFC 3549 2.3.2.2 - only `Some` is a real NACK.
                    if e.code.is_some() {
                        anyhow::bail!("SetDevice netlink error: {:?}", e.to_io());
                    }
                }
            }
            None => tracing::debug!(
                "SetDevice got no response at all (expected an ack/nack, but proceeding)"
            ),
        }
        Ok(())
    }
}
