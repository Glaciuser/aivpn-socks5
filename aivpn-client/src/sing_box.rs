use serde_json::{json, Value};

use crate::local_socks::LocalSocks5Config;

pub const DEFAULT_SING_BOX_LISTEN_HOST: &str = "127.0.0.1";
pub const DEFAULT_SING_BOX_LISTEN_PORT: u16 = 2080;
pub const AIVPN_SOCKS5_OUTBOUND_TAG: &str = "aivpn-socks5";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingBoxTransportMode {
    Tun,
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxEndpoint {
    pub host: String,
    pub port: u16,
}

impl SingBoxEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

impl From<&LocalSocks5Config> for SingBoxEndpoint {
    fn from(config: &LocalSocks5Config) -> Self {
        Self::new(config.host.clone(), config.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxTunOptions {
    pub interface_name: String,
    pub address: String,
    pub mtu: u16,
}

impl Default for SingBoxTunOptions {
    fn default() -> Self {
        Self {
            interface_name: "aivpn-sb0".to_string(),
            address: "172.19.0.1/30".to_string(),
            mtu: 9000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxConfigOptions {
    pub transport_mode: SingBoxTransportMode,
    pub listen: SingBoxEndpoint,
    pub aivpn_socks5: SingBoxEndpoint,
    pub tun: SingBoxTunOptions,
    pub log_level: String,
}

impl SingBoxConfigOptions {
    pub fn openwrt_socks5(local_socks5: &LocalSocks5Config) -> Self {
        Self {
            transport_mode: SingBoxTransportMode::Socks5,
            listen: SingBoxEndpoint::new(
                DEFAULT_SING_BOX_LISTEN_HOST,
                DEFAULT_SING_BOX_LISTEN_PORT,
            ),
            aivpn_socks5: SingBoxEndpoint::from(local_socks5),
            tun: SingBoxTunOptions::default(),
            log_level: "warn".to_string(),
        }
    }
}

pub fn generate_openwrt_config(options: &SingBoxConfigOptions) -> Value {
    let inbound = match options.transport_mode {
        SingBoxTransportMode::Socks5 => json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": options.listen.host.as_str(),
            "listen_port": options.listen.port,
            "set_system_proxy": false
        }),
        SingBoxTransportMode::Tun => json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": options.tun.interface_name.as_str(),
            "address": [options.tun.address.as_str()],
            "mtu": options.tun.mtu,
            "auto_route": true,
            "strict_route": true
        }),
    };

    json!({
        "log": {
            "level": options.log_level.as_str(),
            "timestamp": true
        },
        "inbounds": [inbound],
        "outbounds": [
            {
                "type": "socks",
                "tag": AIVPN_SOCKS5_OUTBOUND_TAG,
                "server": options.aivpn_socks5.host.as_str(),
                "server_port": options.aivpn_socks5.port,
                "version": "5"
            },
            {
                "type": "direct",
                "tag": "direct"
            },
            {
                "type": "block",
                "tag": "block"
            }
        ],
        "route": {
            "final": AIVPN_SOCKS5_OUTBOUND_TAG,
            "auto_detect_interface": false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_contains_string(value: &Value, needle: &str) -> bool {
        match value {
            Value::String(value) => value == needle,
            Value::Array(items) => items.iter().any(|item| value_contains_string(item, needle)),
            Value::Object(map) => map
                .iter()
                .any(|(key, value)| key == needle || value_contains_string(value, needle)),
            _ => false,
        }
    }

    #[test]
    fn openwrt_socks5_config_uses_socks_outbound() {
        let local_socks5 = LocalSocks5Config {
            host: "127.0.0.1".to_string(),
            port: 1080,
            max_clients: 1024,
            max_concurrent_dials: 512,
        };

        let config = generate_openwrt_config(&SingBoxConfigOptions::openwrt_socks5(&local_socks5));

        let outbound = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outbound| outbound["tag"] == AIVPN_SOCKS5_OUTBOUND_TAG)
            .unwrap();
        assert_eq!(outbound["type"], "socks");
        assert_eq!(outbound["server"], "127.0.0.1");
        assert_eq!(outbound["server_port"], 1080);
        assert_eq!(outbound["version"], "5");
    }

    #[test]
    fn openwrt_socks5_config_has_no_tun_or_route_automation_sections() {
        let config = generate_openwrt_config(&SingBoxConfigOptions::openwrt_socks5(
            &LocalSocks5Config::default(),
        ));

        for forbidden in [
            "tun",
            "auto_route",
            "auto_redirect",
            "strict_route",
            "interface_name",
            "route_address",
            "inet4_address",
            "inet6_address",
        ] {
            assert!(
                !value_contains_string(&config, forbidden),
                "SOCKS5 sing-box config unexpectedly contains {forbidden}"
            );
        }
    }

    #[test]
    fn transport_mode_selects_tun_or_socks5_inbound() {
        let local_socks5 = LocalSocks5Config::default();
        let socks_config =
            generate_openwrt_config(&SingBoxConfigOptions::openwrt_socks5(&local_socks5));
        assert_eq!(socks_config["inbounds"][0]["type"], "mixed");

        let mut tun_options = SingBoxConfigOptions::openwrt_socks5(&local_socks5);
        tun_options.transport_mode = SingBoxTransportMode::Tun;
        let tun_config = generate_openwrt_config(&tun_options);
        assert_eq!(tun_config["inbounds"][0]["type"], "tun");
        assert_eq!(tun_config["inbounds"][0]["address"][0], "172.19.0.1/30");
    }

    #[test]
    fn generation_is_deterministic() {
        let options = SingBoxConfigOptions::openwrt_socks5(&LocalSocks5Config::default());
        let first = serde_json::to_string_pretty(&generate_openwrt_config(&options)).unwrap();
        let second = serde_json::to_string_pretty(&generate_openwrt_config(&options)).unwrap();

        assert_eq!(first, second);
    }
}
