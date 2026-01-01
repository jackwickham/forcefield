use std::net::{IpAddr, Ipv4Addr};

use axum::http::{HeaderName, Request};
use tower_governor::{GovernorError, key_extractor::KeyExtractor};

/// Key extractor that reads client IP from a configured header,
/// falling back to the connecting socket address.
#[derive(Clone)]
pub struct ClientIpKeyExtractor {
    header_name: Option<HeaderName>,
}

impl ClientIpKeyExtractor {
    pub fn new(header_name: Option<HeaderName>) -> Self {
        Self { header_name }
    }
}

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        // Try to get IP from configured header first
        if let Some(ip) = self
            .header_name
            .as_ref()
            .and_then(|header_name| req.headers().get(header_name))
            .and_then(|header_value| header_value.to_str().ok())
            .and_then(|ip| ip.trim().parse::<IpAddr>().ok())
        {
            return Ok(ip);
        }

        // Fall back to connecting socket address
        Ok(req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|connect_info| connect_info.0.ip())
            // Use localhost as fallback (e.g., in tests where ConnectInfo isn't available)
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use axum::{extract::ConnectInfo, http::Request};
    use tower_governor::key_extractor::KeyExtractor;

    #[test]
    fn no_header_no_connect_info_returns_localhost() {
        let extractor = ClientIpKeyExtractor::new(None);
        let req = Request::builder().body(()).unwrap();

        let ip = extractor.extract(&req).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn no_header_with_connect_info_returns_socket_ip() {
        let extractor = ClientIpKeyExtractor::new(None);
        let socket_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(ConnectInfo(socket_addr));

        let ip = extractor.extract(&req).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn header_configured_but_missing_falls_back_to_connect_info() {
        let extractor = ClientIpKeyExtractor::new(Some("X-Real-IP".parse().unwrap()));
        let socket_addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let mut req = Request::builder().body(()).unwrap();
        req.extensions_mut().insert(ConnectInfo(socket_addr));

        let ip = extractor.extract(&req).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn header_configured_but_missing_falls_back_to_localhost() {
        let extractor = ClientIpKeyExtractor::new(Some("X-Real-IP".parse().unwrap()));
        let req = Request::builder().body(()).unwrap();

        let ip = extractor.extract(&req).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn extracts_ipv4_from_header() {
        let extractor = ClientIpKeyExtractor::new(Some("X-Real-IP".parse().unwrap()));
        let req = Request::builder()
            .header("X-Real-IP", "203.0.113.50")
            .body(())
            .unwrap();

        let ip = extractor.extract(&req).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)));
    }

    #[test]
    fn extracts_ipv6_from_header() {
        let extractor = ClientIpKeyExtractor::new(Some("X-Forwarded-For".parse().unwrap()));
        let req = Request::builder()
            .header("X-Forwarded-For", "2001:db8::1")
            .body(())
            .unwrap();

        let ip = extractor.extract(&req).unwrap();
        assert_eq!(
            ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn trims_whitespace_from_header_value() {
        let extractor = ClientIpKeyExtractor::new(Some("X-Real-IP".parse().unwrap()));
        let req = Request::builder()
            .header("X-Real-IP", "  172.16.0.1  ")
            .body(())
            .unwrap();

        let ip = extractor.extract(&req).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
    }

    #[test]
    fn invalid_ip_in_header_falls_back_to_connect_info() {
        let extractor = ClientIpKeyExtractor::new(Some("X-Real-IP".parse().unwrap()));
        let socket_addr: SocketAddr = "10.20.30.40:9000".parse().unwrap();
        let mut req = Request::builder()
            .header("X-Real-IP", "not-an-ip")
            .body(())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(socket_addr));

        let ip = extractor.extract(&req).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)));
    }

    #[test]
    fn header_takes_precedence_over_connect_info() {
        let extractor = ClientIpKeyExtractor::new(Some("X-Real-IP".parse().unwrap()));
        let socket_addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let mut req = Request::builder()
            .header("X-Real-IP", "203.0.113.99")
            .body(())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(socket_addr));

        let ip = extractor.extract(&req).unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99)));
    }
}
